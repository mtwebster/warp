#!/usr/bin/python3

import asyncio
import os
import gettext
import logging
import time
import re
import ipaddress
import urllib
from concurrent.futures import ThreadPoolExecutor

from gi.repository import GObject, GLib

import grpc
import grpc.aio
import warp_pb2
import warp_pb2_grpc
from google import protobuf

import config
import auth
import interceptors
import networkmonitor
import remote
import remote_registration
import prefs
import util
import misc
import transfers
from ops import ReceiveOp, TextMessageOp
from util import TransferDirection, OpStatus, RemoteStatus, RemoteFeatures, ReceiveError

import zeroconf
from zeroconf import ServiceInfo, IPVersion
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser, AsyncServiceInfo

_ = gettext.gettext

void = warp_pb2.VoidType()

SERVICE_TYPE = "_warpinator._tcp.local."

SERVER_FEATURES = RemoteFeatures.TEXT_MESSAGES


class Server(warp_pb2_grpc.WarpServicer, GObject.Object):
    __gsignals__ = {
        "remote-machine-added": (GObject.SignalFlags.RUN_LAST, None, (object,)),
        "remote-machine-removed": (GObject.SignalFlags.RUN_LAST, None, (object,)),
        "remote-machine-ops-changed": (GObject.SignalFlags.RUN_LAST, None, (str,)),
        "local-info-changed": (GObject.SignalFlags.RUN_LAST, None, (str,)),
        "server-started": (GObject.SignalFlags.RUN_LAST, None, ()),
        "shutdown-complete": (GObject.SignalFlags.RUN_LAST, None, ()),
        "manual-connect-result": (GObject.SignalFlags.RUN_LAST, None, (bool, bool, str)),
    }

    def __init__(self, ip_info, port, auth_port):
        super(Server, self).__init__()
        GObject.Object.__init__(self)

        self.service_name = None
        self.service_ident = None

        self.ip_info = ip_info
        self.port = port
        self.auth_port = auth_port

        self.untrusted_remote_machines = {}
        self.remote_machines = {}
        self.remote_registrar = None

        self.netmon = networkmonitor.get_network_monitor()

        self.server = None
        self.browser4 = None
        self.browser6 = None
        self.aiozc = None
        self.info = None
        self.browser_mutex = asyncio.Lock()

        self.display_name = GLib.get_real_name()

        # Lifecycle
        self._loop = asyncio.get_event_loop()
        self._shutdown_event = asyncio.Event()
        self._run_task = None
        self._shutdown_complete = False

        # Schedule the run() coroutine; it cooperates with the GLib main loop via
        # gi.events.GLibEventLoopPolicy or gbulb (installed in warpinator.py main()).
        self._run_task = self._loop.create_task(self.run())

    # --- threading.Thread API compatibility shims (used by warpinator.py do_shutdown) ---

    def is_alive(self):
        return self._run_task is not None and not self._run_task.done()

    def join(self, timeout=None):
        # The run() task lives on the GLib/asyncio loop. Caller in do_shutdown is
        # iterating that loop until is_alive() returns False, so by the time we
        # land here the task is already done. Provided for API parity.
        return

    # --- Zeroconf service registration & browsing ---

    async def start_zeroconf(self):
        logging.info("Using zeroconf version %s %s" % (zeroconf.__version__, "(bundled)" if config.bundle_zeroconf else ""))

        ip_addresses = []
        if self.ip_info.ip4_address is not None:
            ip_addresses.append(self.ip_info.ip4_address)
        if self.ip_info.ip6_address is not None:
            ip_addresses.append(self.ip_info.ip6_address)
        self.aiozc = AsyncZeroconf(interfaces=ip_addresses)

        self.service_ident = prefs.get_connect_id()
        self.service_name = "%s.%s" % (self.service_ident, SERVICE_TYPE)

        # If this process is killed (either kill or network issue), the service
        # never gets unregistered, which will prevent remotes from seeing us
        # when we come back.  Our first service info is to get us back on
        # momentarily, and the unregister properly, so remotes get notified.
        # Then we'll do it again without the flush property for the real
        # connection.

        init_info = ServiceInfo(SERVICE_TYPE,
                                self.service_name,
                                port=self.port,
                                addresses=self.ip_info.as_binary_list(),
                                properties={ 'hostname': util.get_hostname(),
                                             'type': 'flush' })

        await self.aiozc.async_register_service(init_info)
        await asyncio.sleep(3)
        await self.aiozc.async_unregister_service(init_info)
        await asyncio.sleep(3)

        self.info = ServiceInfo(SERVICE_TYPE,
                                self.service_name,
                                port=self.port,
                                addresses=self.ip_info.as_binary_list(),
                                properties={ 'hostname': util.get_hostname(),
                                             'api-version': config.RPC_API_VERSION,
                                             'auth-port': str(prefs.get_auth_port()),
                                             'type': 'real' })

        await self.aiozc.async_register_service(self.info)
        # AsyncServiceBrowser can only do one IP version per instance.
        if self.ip_info.ip4_address is not None:
            self.browser4 = AsyncServiceBrowser(self.aiozc.zeroconf, SERVICE_TYPE, listener=self, addr=self.ip_info.ip4_address)
        if self.ip_info.ip6_address is not None:
            self.browser6 = AsyncServiceBrowser(self.aiozc.zeroconf, SERVICE_TYPE, listener=self, addr=self.ip_info.ip6_address)

    # AsyncServiceBrowser's listener dispatcher invokes these as regular
    # callables — it doesn't await coroutines. Keep them sync and fan out the
    # actual work as asyncio tasks on the running loop.
    def update_service(self, zeroconf, _type, name):
        pass

    def remove_service(self, zeroconf, _type, name):
        asyncio.create_task(self._on_remove_service(zeroconf, _type, name))

    def add_service(self, zeroconf, _type, name):
        asyncio.create_task(self._on_add_service(zeroconf, _type, name))

    async def _on_remove_service(self, zeroconf, _type, name):
        if name == self.service_name:
            return

        ident = name.partition(".%s" % SERVICE_TYPE)[0]

        try:
            r = self.remote_machines[ident]
        except KeyError:
            logging.debug(">>> Discovery: unknown service ident (%s) reported as gone by zc." % ident)
            return

        logging.debug(">>> Discovery: service %s (%s:%d) has disappeared."
                          % (r.display_hostname, r.ip_info, r.port))

        r.has_zc_presence = False

    async def _on_add_service(self, zeroconf, _type, name):
        async with self.browser_mutex:
            info = AsyncServiceInfo(_type, name)
            if not await info.async_request(self.aiozc.zeroconf, 3000):
                return

            ident = name.partition(".%s" % SERVICE_TYPE)[0]

            try:
                remote_hostname = info.properties[b"hostname"].decode()
            except KeyError:
                logging.critical(">>> Discovery: no hostname in service info properties.  Is this an old version?")
                return

            remote_ip_info = util.RemoteInterfaceInfo(info.addresses_by_version(IPVersion.All))

            if remote_ip_info == self.ip_info:
                return

            try:
                if info.properties[b"type"].decode() == "flush":
                    logging.debug(">>> Discovery: received flush service info (ignoring): %s (%s:%d)"
                                    % (remote_hostname, remote_ip_info, info.port))
                    return
            except KeyError:
                logging.warning("No type in service info properties, assuming this is a real connect attempt")

            if ident == self.service_ident:
                return

            try:
                api_version = info.properties[b"api-version"].decode()
                auth_port = int(info.properties[b"auth-port"].decode())
            except KeyError:
                api_version = "1"
                auth_port = 0

            # FIXME: I'm not sure why we still get discovered by other networks in some cases -
            # The Zeroconf object has a specific ip it is set to, what more do I need to do?
            if not self.netmon.same_subnet(remote_ip_info):
                logging.debug(">>> Discovery: service is not on this subnet, ignoring: %s (%s)" % (remote_hostname, remote_ip_info))
                return

            cert_result = util.CertProcessingResult.FAILURE
            newly_discovered = False
            try:
                machine = self.remote_machines[ident]
                machine.has_zc_presence = True
                logging.info(">>> Discovery: existing remote: %s (%s:%d)"
                                % (machine.display_hostname, remote_ip_info, info.port))

                # If the remote truly is the same one (our service info just dropped out
                # momentarily), this will end up just retrieving the current cert again.
                # If this was a real disconnect we didn't notice, we'll have the new cert
                # which we'll need when our supposedly existing connection tries to continue
                # pinging. It will fail out and restart the connection loop, and will need
                # this updated one.
                if not machine.status in (RemoteStatus.INIT_CONNECTING, RemoteStatus.AWAITING_DUPLEX):
                    now = time.time()
                    if now - machine.last_register > 15:
                        cert_result = await self.remote_registrar.register_async(
                            ident, remote_hostname, remote_ip_info, info.port, auth_port, api_version)
                        if cert_result == util.CertProcessingResult.FAILURE or self._shutdown_event.is_set():
                            logging.warning("Register failed, or the server was shutting down during registration, ignoring remote %s (%s:%d) auth port: %d"
                                            % (remote_hostname, remote_ip_info, info.port, auth_port))
                            return

                        if machine.status == RemoteStatus.ONLINE:
                            logging.debug(">>> Discovery: rejoining existing connect with %s (%s:%d)"
                                        % (machine.display_hostname, remote_ip_info, info.port))
                            return

                        machine.hostname = remote_hostname
                        machine.ip_info = remote_ip_info
                        machine.port = info.port
                        machine.api_version = api_version
            except KeyError:
                newly_discovered = True
                display_hostname = self.ensure_unique_hostname(remote_hostname)

                logging.info(">>> Discovery: new remote: %s (%s:%d)"
                                % (display_hostname, remote_ip_info, info.port))

                machine = remote.RemoteMachine(ident,
                                            remote_hostname,
                                            display_hostname,
                                            remote_ip_info,
                                            info.port,
                                            self.service_ident,
                                            api_version,
                                            self._loop)
                machine.last_register = time.time()
                cert_result = await self.remote_registrar.register_async(
                    ident, remote_hostname, remote_ip_info, info.port, auth_port, api_version)
                if cert_result == util.CertProcessingResult.FAILURE or self._shutdown_event.is_set():
                    logging.debug("Register failed, or the server was shutting down during registration, ignoring remote %s (%s:%d) auth port: %d"
                                    % (remote_hostname, remote_ip_info, info.port, auth_port))
                    return

                self.remote_machines[ident] = machine
                machine.connect("ops-changed", self.remote_ops_changed)
                machine.connect("remote-status-changed", self.remote_status_changed)
                self.idle_emit("remote-machine-added", machine)

            machine.has_zc_presence = True

            if cert_result in (util.CertProcessingResult.CERT_INSERTED, util.CertProcessingResult.CERT_UPDATED) or \
                    (cert_result == util.CertProcessingResult.CERT_UP_TO_DATE and (newly_discovered or machine.status == RemoteStatus.OFFLINE)):
                machine.shutdown()  # No-op if not running. Ensures any prior task has finished.
                machine.start_remote_thread()

    def register_with_host(self, host: str):
        # Called from the UI (GLib loop thread); schedule the async coroutine.
        self._loop.call_soon_threadsafe(
            lambda: self._loop.create_task(self._register_with_host(host))
        )

    async def _register_with_host(self, host: str):
        try:
            if not host.startswith("warpinator://"):
                host = "warpinator://%s" % host
            url = urllib.parse.urlparse(host)
            ipaddress.ip_address(url.hostname)
        except ValueError:
            logging.info("User tried to connect to invalid address %s" % host)
            self.idle_emit("manual-connect-result", True, False, "Invalid address")
            return

        host = url.netloc
        logging.info("Registering with " + host)
        async with grpc.aio.insecure_channel(host) as channel:
            try:
                await asyncio.wait_for(channel.channel_ready(), timeout=5)
                stub = warp_pb2_grpc.WarpRegistrationStub(channel)
                reg = await asyncio.wait_for(
                    stub.RegisterService(warp_pb2.ServiceRegistration(
                        service_id=self.service_ident,
                        ip=self.ip_info.ip4_address, port=self.port,
                        hostname=util.get_hostname(), api_version=int(config.RPC_API_VERSION),
                        auth_port=self.auth_port, ipv6=self.ip_info.ip6_address)),
                    timeout=5,
                )
                await self.handle_manual_service_registration(reg, True)
            except Exception as e:
                logging.critical("Could not register with %s, err %s" % (host, e))
                self.idle_emit("manual-connect-result", True, False, "Could not connect to remote")

    async def handle_manual_service_registration(self, reg, initiated_here=False):
        ip4_addr = None
        ip6_addr = None
        try:
            ip4_addr = ipaddress.ip_address(reg.ip)
        except ValueError:
            pass
        try:
            ip6_addr = ipaddress.ip_address(reg.ipv6)
        except ValueError:
            pass
        if reg.service_id in self.remote_machines.keys():
            machine = self.remote_machines[reg.service_id]
            if machine.status == RemoteStatus.ONLINE:
                logging.debug("Host %s:%d was already connected" % (machine.ip_info, reg.auth_port))
                self.idle_emit("manual-connect-result", initiated_here, True, "Already connected")
                return
            if (await self.remote_registrar.register_async(machine.ident, machine.hostname, machine.ip_info, machine.port, reg.auth_port, machine.api_version)) == util.CertProcessingResult.FAILURE or self._shutdown_event.is_set():
                logging.debug("Registration of static machine failed, ignoring remote %s (%s:%d) auth %d" % (reg.hostname, machine.ip_info, reg.port, reg.auth_port))
                self.idle_emit("manual-connect-result", initiated_here, False, "Authentication failed")
                return
            machine.hostname = reg.hostname
            if isinstance(ip4_addr, ipaddress.IPv4Address):
                machine.ip_info.ip4_address = str(ip4_addr)
            if isinstance(ip6_addr, ipaddress.IPv6Address):
                machine.ip_info.ip6_address = str(ip6_addr)
            machine.port = reg.port
            machine.api_version = str(reg.api_version)

            machine.shutdown()
            machine.start_remote_thread()
        else:
            logging.debug("Adding new static machine (manual connection)")
            display_hostname = self.ensure_unique_hostname(reg.hostname)
            ip_info = util.RemoteInterfaceInfo([])
            if isinstance(ip4_addr, ipaddress.IPv4Address):
                ip_info.ip4_address = str(ip4_addr)
            if isinstance(ip6_addr, ipaddress.IPv6Address):
                ip_info.ip6_address = str(ip6_addr)
            machine = remote.RemoteMachine(reg.service_id, reg.hostname, display_hostname, ip_info, reg.port, self.service_ident, str(reg.api_version), self._loop)
            if (await self.remote_registrar.register_async(machine.ident, machine.hostname, machine.ip_info, machine.port, reg.auth_port, machine.api_version)) == util.CertProcessingResult.FAILURE or self._shutdown_event.is_set():
                logging.debug("Registration of static machine failed, ignoring remote %s (%s:%d) auth %d"
                                    % (machine.hostname, machine.ip_info.ip4_address, machine.port, reg.auth_port))
                self.idle_emit("manual-connect-result", initiated_here, False, "Authentication failed")
                return
            self.remote_machines[machine.ident] = machine
            machine.connect("ops-changed", self.remote_ops_changed)
            machine.connect("remote-status-changed", self.remote_status_changed)
            self.idle_emit("remote-machine-added", machine)
            machine.start_remote_thread()
        self.idle_emit("manual-connect-result", initiated_here, True, "Connected")

    def ensure_unique_hostname(self, hostname):
        display_hostname = hostname
        i = 1
        while True:
            found = False

            for key in self.remote_machines.keys():
                remote_machine = self.remote_machines[key]

                if remote_machine.display_hostname == display_hostname:
                    display_hostname = "%s[%d]" % (hostname, i)
                    found = True
                    break

            i += 1
            if not found:
                break

        return display_hostname

    async def run(self):
        try:
            logging.info("Using grpc version %s %s" % (grpc.__version__, "(bundled)" if config.bundle_grpc else ""))
            logging.info("Using protobuf version %s %s" % (protobuf.__version__, "(bundled)" if config.bundle_grpc else ""))
            logging.debug("Server: starting server on %s (%s)" % (self.ip_info, self.ip_info.iface))
            logging.info("Using api version %s" % config.RPC_API_VERSION)
            logging.info("Our uuid: %s" % prefs.get_connect_id())

            self.remote_registrar = remote_registration.Registrar(self.ip_info, self.port, self.auth_port, self._loop)
            self.remote_registrar.reg_server_v2.service_registration_handler = self.handle_manual_service_registration
            await self.remote_registrar.start()

            options = (
                ('grpc.keepalive_time_ms', 10 * 1000),
                ('grpc.keepalive_timeout_ms', 5 * 1000),
                ('grpc.keepalive_permit_without_calls', True),
                ('grpc.http2.max_pings_without_data', 0),
                ('grpc.http2.min_time_between_pings_ms', 10 * 1000),
                ('grpc.http2.min_ping_interval_without_data_ms', 5 * 1000),
            )

            self.server = grpc.aio.server(
                options=options,
                interceptors=[interceptors.ChunkCompressor()],
            )
            warp_pb2_grpc.add_WarpServicer_to_server(self, self.server)

            pair = auth.get_singleton().get_server_creds()
            server_credentials = grpc.ssl_server_credentials((pair,))

            if self.ip_info.ip4_address:
                self.server.add_secure_port('%s:%d' % (self.ip_info.ip4_address, self.port),
                                            server_credentials)
            if self.ip_info.ip6_address:
                self.server.add_secure_port('[%s]:%d' % (self.ip_info.ip6_address, self.port),
                                            server_credentials)
            await self.server.start()

            self._shutdown_event.clear()

            try:
                await self.start_zeroconf()
            except Exception as e:
                logging.critical("Zeroconf failed to start, server will terminate: %s" % e)
                self._shutdown_event.set()

            self.idle_emit("server-started")

            logging.info("Server: ACTIVE")

            # **** RUNNING ****
            await self._shutdown_event.wait()
            # **** STOPPING ****

            await self.remote_registrar.shutdown_registration_servers()
            self.remote_registrar = None

            logging.debug("Server: stopping discovery and advertisement")

            try:
                if self.browser4 is not None:
                    await self.browser4.async_cancel()
                if self.browser6 is not None:
                    await self.browser6.async_cancel()
                if self.aiozc is not None:
                    await self.aiozc.async_close()
            except Exception:
                logging.critical("Can't close Zeroconf - maybe it failed to start")

            remote_machines = list(self.remote_machines.values())
            for r in remote_machines:
                self.idle_emit("remote-machine-removed", r)
                logging.debug("Server: Closing connection to remote machine %s (%s:%d)"
                                  % (r.display_hostname, r.ip_info.ip4_address, r.port))
                r.shutdown()
            for r in remote_machines:
                await r.wait_until_done()
            remote_machines = None

            logging.debug("Server: terminating server")
            await self.server.stop(grace=2)

            self.idle_emit("shutdown-complete")
            self.server = None

            logging.debug("Server: server stopped")
        finally:
            self._shutdown_complete = True

    def shutdown(self):
        self._shutdown_event.set()

    def remote_status_changed(self, remote):
        if remote.status == RemoteStatus.OFFLINE:
            self.emit("remote-machine-removed", remote)

    def add_receive_op_to_remote_machine(self, op):
        self.remote_machines[op.sender].add_op(op)

    @misc._idle
    def remote_ops_changed(self, remote_machine):
        self.emit("remote-machine-ops-changed", remote_machine.ident)

    def list_remote_machines(self):
        return self.remote_machines.values()

    def get_active_op_count(self, incoming_only=False):
        count = 0

        for machine in self.remote_machines.values():
            if machine.status != RemoteStatus.ONLINE:
                continue
            for op in machine.transfer_ops:
                if incoming_only and not isinstance(op, ReceiveOp):
                    continue
                if op.status == OpStatus.TRANSFERRING:
                    count += 1

        return count

    def cancel_all_ops(self):
        for machine in self.remote_machines.values():
            if machine.status != RemoteStatus.ONLINE:
                continue
            for op in machine.transfer_ops:
                if op.status == OpStatus.TRANSFERRING:
                    op.stop_transfer()

    @misc._idle
    def idle_emit(self, signal, *callback_data):
        self.emit(signal, *callback_data)

    # ---- Servicer methods (now async; the WarpServicer interface accepts both) ----

    async def Ping(self, request, context):
        logging.debug("Server Ping: from %s" % request.readable_name)

        try:
            self.remote_machines[request.id]
        except KeyError:
            logging.debug("Server Ping: ping is from unknown remote (or not fully online yet)")

        return void

    async def CheckDuplexConnection(self, request, context):
        logging.debug("Server RPC: CheckDuplexConnection from '%s'" % request.readable_name)
        response = False

        try:
            r = self.remote_machines[request.id]
            response = (r.status in (RemoteStatus.AWAITING_DUPLEX, RemoteStatus.ONLINE))
        except KeyError:
            pass

        return warp_pb2.HaveDuplex(response=response)

    async def WaitingForDuplex(self, request, context):
        logging.debug("Server RPC: WaitingForDuplex from '%s' (api v2)" % request.readable_name)

        max_tries = 20
        i = 0

        # try for ~5 seconds (the caller aborts at 4)
        while i < max_tries:
            response = False

            try:
                r = self.remote_machines[request.id]
                response = (r.status in (RemoteStatus.AWAITING_DUPLEX, RemoteStatus.ONLINE))
            except KeyError:
                pass

            if response:
                break
            i += 1
            if i == max_tries:
                await context.abort(code=grpc.StatusCode.DEADLINE_EXCEEDED,
                                    details='Server timed out while waiting for his corresponding remote to connect back to you.')
                return
            await asyncio.sleep(.25)

        return warp_pb2.HaveDuplex(response=response)

    async def GetRemoteMachineInfo(self, request, context):
        logging.debug("Server RPC: GetRemoteMachineInfo from '%s'" % request.readable_name)

        return warp_pb2.RemoteMachineInfo(display_name=GLib.get_real_name(),
                                          user_name=GLib.get_user_name(),
                                          feature_flags=SERVER_FEATURES)

    async def GetRemoteMachineAvatar(self, request, context):
        logging.debug("Server RPC: GetRemoteMachineAvatar from '%s'" % request.readable_name)

        path = os.path.join(GLib.get_home_dir(), ".face")
        if not os.path.exists(path):
            await context.abort(code=grpc.StatusCode.NOT_FOUND, details='.face file not found!')
            return

        async for chunk in transfers.load_file_in_chunks(path):
            yield chunk

    async def ProcessTransferOpRequest(self, request, context):
        logging.debug("Server RPC: ProcessTransferOpRequest from '%s'" % request.info.readable_name)

        try:
            remote_machine = self.remote_machines[request.info.ident]
        except KeyError as e:
            logging.warning("Received transfer op request for unknown remote: %s" % e)
            return void

        for existing_op in remote_machine.transfer_ops:
            if existing_op.start_time == request.info.timestamp:
                try:
                    existing_op.use_compression = request.info.use_compression
                except AttributeError:
                    existing_op.use_compression = False
                existing_op.set_status(OpStatus.WAITING_PERMISSION)
                self.add_receive_op_to_remote_machine(existing_op)
                return void

        op = ReceiveOp(request.info.ident)

        op.start_time = request.info.timestamp

        op.sender_name = request.sender_name
        op.receiver = request.receiver
        op.receiver_name = request.receiver_name
        op.status = OpStatus.WAITING_PERMISSION
        op.total_size = request.size
        op.total_count = op.remaining_count = request.count
        op.mime_if_single = request.mime_if_single
        op.name_if_single = request.name_if_single
        op.top_dir_basenames = request.top_dir_basenames

        try:
            op.use_compression = request.info.use_compression
        except AttributeError:
            op.use_compression = False

        op.connect("initial-setup-complete", self.add_receive_op_to_remote_machine)
        op.prepare_receive_info()

        return void

    async def CancelTransferOpRequest(self, request, context):
        logging.debug("Server RPC: CancelTransferOpRequest from '%s'" % request.readable_name)

        try:
            op = self.remote_machines[request.ident].lookup_op(request.timestamp)
        except KeyError as e:
            logging.warning("Received cancel transfer op request for unknown op: %s" % e)
            return void

        # If we receive this call, this means the op was cancelled remotely.  So,
        # our op with TO_REMOTE_MACHINE (we initiated it) was cancelled by the recipient.
        if op.direction == TransferDirection.TO_REMOTE_MACHINE:
            op.set_status(OpStatus.CANCELLED_PERMISSION_BY_RECEIVER)
        else:
            op.set_status(OpStatus.CANCELLED_PERMISSION_BY_SENDER)

        return void

    # receiver server responders
    async def StartTransfer(self, request, context):
        logging.debug("Server RPC: StartTransfer from '%s'" % request.readable_name)

        start_time = GLib.get_monotonic_time()

        try:
            self.remote_machines[request.ident]
        except KeyError as e:
            logging.warning("Server: start transfer is from unknown remote: %s" % e)
            return

        try:
            op = self.remote_machines[request.ident].lookup_op(request.timestamp)
        except KeyError as e:
            logging.warning("Server: start transfer for unknowns op: %s" % e)
            return

        cancellable = asyncio.Event()
        op.file_send_cancellable = cancellable

        op.set_status(OpStatus.TRANSFERRING)

        op.progress_tracker = transfers.OpProgressTracker(op)
        op.current_progress_report = None
        sender = transfers.FileSender(op, request.timestamp, cancellable)

        try:
            async for chunk in sender.read_chunks():
                yield chunk
        finally:
            if sender.error is not None:
                op.set_error(sender.error)
                op.set_status(OpStatus.FAILED_UNRECOVERABLE)
            elif op.file_send_cancellable.is_set():
                logging.debug("Server: file send cancelled")
            else:
                logging.debug("Server: transfer of %s files (%s) finished in %s" %
                    (op.total_count, GLib.format_size(op.total_size),
                     util.precise_format_time_span(GLib.get_monotonic_time() - start_time)))

    async def StopTransfer(self, request, context):
        logging.debug("Server RPC: StopTransfer from '%s'" % request.info.readable_name)

        try:
            op = self.remote_machines[request.info.ident].lookup_op(request.info.timestamp)
        except KeyError as e:
            logging.warning("Server: stop transfer was for unknown op: %s" % e)
            return void

        if request.error:
            op.error_msg = _("An error occurred on the remote machine")

        if op.direction == TransferDirection.TO_REMOTE_MACHINE:
            if op.file_send_cancellable is not None:
                op.file_send_cancellable.set()
            logging.debug("Server: sender received stop transfer by receiver: %s" % op.error_msg)
            if op.error_msg == "":
                op.set_status(OpStatus.STOPPED_BY_RECEIVER)
            else:
                op.set_status(OpStatus.FAILED)
        else:
            try:
                op.file_iterator.cancel()
            except AttributeError:
                # we may not have this yet if the transfer fails upon the initial response
                # (meaning we haven't returned the generator)
                pass
            logging.debug("Server: receiver received stop transfer by sender: %s" % op.error_msg)
            if op.error_msg == "":
                op.set_status(OpStatus.STOPPED_BY_SENDER)
            else:
                op.set_status(OpStatus.FAILED)

        return void

    async def SendTextMessage(self, request, context):
        logging.debug("Server RPC: SendTextMessage from '%s'" % request.ident)
        try:
            remote_machine: remote.RemoteMachine = self.remote_machines[request.ident]
        except KeyError as e:
            logging.warning("Received text message from unknown remote: %s" % e)
            return void

        op = TextMessageOp(TransferDirection.FROM_REMOTE_MACHINE, request.ident)
        op.sender_name = remote_machine.display_name
        op.message = request.message
        op.status = OpStatus.FINISHED
        remote_machine.add_op(op)
        op.send_notification()

        return void
