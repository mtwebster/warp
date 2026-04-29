#!/usr/bin/python3

import asyncio
import time
import gettext
import threading
import logging
import socket
from concurrent.futures import ThreadPoolExecutor

from gi.repository import GObject, GLib

import grpc
import grpc.aio
import warp_pb2
import warp_pb2_grpc

import interceptors
import prefs
import util
import misc
import transfers
import auth
from ops import SendOp, ReceiveOp, TextMessageOp
from util import TransferDirection, OpStatus, OpCommand, RemoteStatus, ReceiveError, RemoteFeatures

_ = gettext.gettext

# typedef
void = warp_pb2.VoidType()

CHANNEL_RETRY_WAIT_TIME = 30

DUPLEX_MAX_FAILURES = 10
DUPLEX_WAIT_PING_TIME = 1
CONNECTED_PING_TIME = 20


# client
class RemoteMachine(GObject.Object):
    __gsignals__ = {
        'machine-info-changed': (GObject.SignalFlags.RUN_LAST, None, ()),
        'ops-changed': (GObject.SignalFlags.RUN_LAST, None, ()),
        'new-incoming-op': (GObject.SignalFlags.RUN_LAST, None, (object,)),
        'new-outgoing-op': (GObject.SignalFlags.RUN_LAST, None, (object,)),
        'focus-remote': (GObject.SignalFlags.RUN_LAST, None, ()),
        'remote-status-changed': (GObject.SignalFlags.RUN_LAST, None, ())
    }

    def __init__(self, ident, hostname, display_hostname, ip_info, port, local_ident, api_version, loop=None):
        GObject.Object.__init__(self)
        self.ip_info = ip_info
        self.port = port
        self.ident = ident
        self.local_ident = local_ident
        self.api_version = api_version
        self.hostname = hostname
        self.display_hostname = display_hostname
        self.user_name = ""
        self.display_name = ""
        self.favorite = prefs.get_is_favorite(self.ident)
        self.recent_time = 0
        self.supports_messages = False

        self.avatar_surface = None
        self.transfer_ops = []

        self.sort_key = self.hostname
        self.status = RemoteStatus.INIT_CONNECTING

        self.machine_info_changed_source_id = 0
        self.machine_info_changed_lock = threading.Lock()

        self.status_idle_source_id = 0
        self.status_lock = threading.Lock()

        self.stub = None

        self.busy = False  # Skip keepalive ping when we're busy.

        # Async lifecycle. The loop is captured so the zeroconf worker thread can
        # schedule the connection task safely.
        self._loop = loop or asyncio.get_event_loop()
        self.ping_timer = asyncio.Event()
        self.channel_keepalive = asyncio.Event()
        self._main_task = None

        prefs.prefs_settings.connect("changed::favorites", self.update_favorite_status)

        self.has_zc_presence = False  # currently unused
        self.last_register = 0

    def start_remote_thread(self):
        # Schedule the async connection coroutine. May be called from the
        # zeroconf worker thread, so always go through call_soon_threadsafe.
        if self.api_version == "1":
            coro = self.remote_main_v1()
        else:
            coro = self.remote_main_v2()

        def _start():
            self._main_task = self._loop.create_task(coro)

        self._loop.call_soon_threadsafe(_start)

    async def wait_until_done(self):
        if self._main_task is not None:
            try:
                await self._main_task
            except asyncio.CancelledError:
                pass

    async def remote_main_v1(self):
        self.ping_timer.clear()

        self.emit_machine_info_changed()

        logging.debug("Remote: Attempting to connect to %s (%s) - api version 1" % (self.display_hostname, self.ip_info.ip4_address))

        self.set_remote_status(RemoteStatus.INIT_CONNECTING)

        try:
            while True:
                if not await self._run_secure_loop_v1():
                    break
        except Exception as e:
            logging.critical("!! Major problem starting connection loop for %s (%s:%d): %s"
                                 % (self.display_hostname, self.ip_info, self.port, e))

        self.set_remote_status(RemoteStatus.OFFLINE)

    async def _run_secure_loop_v1(self):
        logging.debug("Remote: Starting a new connection loop for %s (%s:%d)"
                          % (self.display_hostname, self.ip_info, self.port))

        cert = auth.get_singleton().get_cached_cert(self.hostname, self.ip_info)
        creds = grpc.ssl_channel_credentials(cert)

        async with grpc.aio.secure_channel("%s:%d" % (self.ip_info.ip4_address, self.port), creds) as channel:
            try:
                await asyncio.wait_for(channel.channel_ready(), timeout=4)
                self.stub = warp_pb2_grpc.WarpStub(channel)
            except (asyncio.TimeoutError, grpc.aio.AioRpcError):
                self.set_remote_status(RemoteStatus.UNREACHABLE)

                if not self.ping_timer.is_set():
                    logging.debug("Remote: Unable to establish secure connection with %s (%s:%d). Trying again in %ds"
                                      % (self.display_hostname, self.ip_info, self.port, CHANNEL_RETRY_WAIT_TIME))
                    await self._wait_or_set(self.ping_timer, CHANNEL_RETRY_WAIT_TIME)
                    return True

                return False

            duplex_fail_counter = 0
            one_ping = False

            while not self.ping_timer.is_set():
                if self.busy:
                    logging.debug("Remote Ping: Skipping keepalive ping to %s (%s:%d) (busy)"
                                      % (self.display_hostname, self.ip_info, self.port))
                    self.busy = False
                else:
                    try:
                        logging.debug("Remote Ping: to   %s (%s:%d)"
                                      % (self.display_hostname, self.ip_info, self.port))
                        await asyncio.wait_for(
                            self.stub.Ping(warp_pb2.LookupName(id=self.local_ident,
                                                               readable_name=util.get_hostname())),
                            timeout=5,
                        )
                        if not one_ping:
                            self.set_remote_status(RemoteStatus.AWAITING_DUPLEX)
                            if await self.check_duplex_connection():
                                logging.debug("Remote: Connected to %s (%s:%d)"
                                                  % (self.display_hostname, self.ip_info, self.port))

                                self.set_remote_status(RemoteStatus.ONLINE)

                                asyncio.create_task(self.update_remote_machine_info())
                                asyncio.create_task(self.update_remote_machine_avatar())
                                one_ping = True
                            else:
                                duplex_fail_counter += 1
                                if duplex_fail_counter > DUPLEX_MAX_FAILURES:
                                    logging.debug("Remote: CheckDuplexConnection to %s (%s:%d) failed too many times"
                                                      % (self.display_hostname, self.ip_info, self.port))
                                    await self._wait_or_set(self.ping_timer, CHANNEL_RETRY_WAIT_TIME)
                                    return True
                    except (grpc.aio.AioRpcError, asyncio.TimeoutError):
                        logging.debug("Remote: Ping failed, shutting down %s (%s:%d)"
                                          % (self.display_hostname, self.ip_info, self.port))
                        break

                await self._wait_or_set(
                    self.ping_timer,
                    CONNECTED_PING_TIME if self.status == RemoteStatus.ONLINE else DUPLEX_WAIT_PING_TIME,
                )

            # This is reached by the RpcError break above.  If the remote is still discoverable, start
            # the secure loop over.  This could have happened as a result of a quick disco/reconnect,
            # And we don't notice until it has already come back. In this case, try a new connection.
            if self.has_zc_presence and not self.ping_timer.is_set():
                return True

            return False

    async def remote_main_v2(self):
        self.channel_keepalive.clear()

        self.emit_machine_info_changed()

        remote_ip, _, ip_version = self.ip_info.get_usable_ip()
        logging.debug("Remote: Attempting to connect to %s (%s) - api version 2" % (self.display_hostname, remote_ip))
        remote_ip = remote_ip if ip_version == socket.AF_INET else "[%s]" % (remote_ip,)

        self.set_remote_status(RemoteStatus.INIT_CONNECTING)

        cert = auth.get_singleton().get_cached_cert(self.hostname, self.ip_info)
        creds = grpc.ssl_channel_credentials(cert)

        while not self.channel_keepalive.is_set():
            await self._run_secure_loop_v2(remote_ip, creds)

        self.set_remote_status(RemoteStatus.OFFLINE)

    async def _run_secure_loop_v2(self, remote_ip, creds):
        opts = (
            ('grpc.keepalive_time_ms', 10000),
            ('grpc.keepalive_timeout_ms', 5000),
            ('grpc.keepalive_permit_without_calls', True),
            ('grpc.http2.max_pings_without_data', 0),
            ('grpc.http2.min_time_between_pings_ms', 10000),
            ('grpc.http2.min_ping_interval_without_data_ms', 5000),
        )

        async with grpc.aio.secure_channel(
            "%s:%d" % (remote_ip, self.port),
            creds,
            options=opts,
            interceptors=[interceptors.ChunkDecompressor()],
        ) as channel:
            state_watch_task = asyncio.create_task(self._watch_channel_state(channel))
            try:
                try:
                    await asyncio.wait_for(channel.channel_ready(), timeout=4)
                    self.stub = warp_pb2_grpc.WarpStub(channel)

                    self.set_remote_status(RemoteStatus.AWAITING_DUPLEX)

                    await asyncio.wait_for(self.wait_for_duplex(), timeout=10)

                    self.set_remote_status(RemoteStatus.ONLINE)

                    asyncio.create_task(self.update_remote_machine_info())
                    asyncio.create_task(self.update_remote_machine_avatar())

                    logging.info("Connected to %s" % self.display_hostname)
                    while not self.channel_keepalive.is_set():
                        await self._wait_or_set(self.channel_keepalive, .5)
                except asyncio.TimeoutError as e:
                    self.set_remote_status(RemoteStatus.UNREACHABLE)
                    logging.critical("Problem while waiting for channel - api version 2: %s" % e)
                    await self._wait_or_set(self.channel_keepalive, 10)
                except grpc.aio.AioRpcError as e:
                    self.set_remote_status(RemoteStatus.UNREACHABLE)
                    logging.critical("Problem while awaiting duplex response - api version 2: %s - %s"
                                     % (e.code(), e.details()))
                    await self._wait_or_set(self.channel_keepalive, 10)
                except Exception as e:
                    self.set_remote_status(RemoteStatus.UNREACHABLE)
                    logging.critical("General error with remote channel connection - api version 2: %s" % e)
                    await self._wait_or_set(self.channel_keepalive, 10)
            finally:
                state_watch_task.cancel()
                try:
                    await state_watch_task
                except asyncio.CancelledError:
                    pass

    async def _watch_channel_state(self, channel):
        # Equivalent of channel.subscribe(channel_state_changed) in the sync API:
        # if the channel ever leaves READY, trigger our shutdown so the connect
        # loop can re-attempt.
        try:
            current = channel.get_state(try_to_connect=False)
            while not self.channel_keepalive.is_set():
                await channel.wait_for_state_change(current)
                current = channel.get_state(try_to_connect=False)
                if current != grpc.ChannelConnectivity.READY:
                    try:
                        self.shutdown()
                    except Exception:
                        pass
                    return
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    @staticmethod
    async def _wait_or_set(event, timeout):
        # Wait until event is set or timeout elapses; mirrors threading.Event.wait(timeout).
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass

    def shutdown(self):
        if self.api_version == "1":
            self.ping_timer.set()
        else:
            self.channel_keepalive.set()

    def update_favorite_status(self, pspec, data=None):
        old_favorite = self.favorite
        self.favorite = prefs.get_is_favorite(self.ident)

        if old_favorite != self.favorite:
            self.emit_machine_info_changed()

    def stamp_recent_time(self):
        self.recent_time = GLib.get_monotonic_time()
        self.emit_machine_info_changed()

    def set_remote_status(self, status):
        with self.status_lock:
            if self.status_idle_source_id > 0:
                GLib.source_remove(self.status_idle_source_id)

            self.status_idle_source_id = GLib.idle_add(self.set_status_cb, status)

    def set_status_cb(self, status):
        with self.status_lock:
            self.status_idle_source_id = 0

            if status == self.status:
                return GLib.SOURCE_REMOVE

            self.status = status
            self.cancel_ops_if_offline()

            logging.debug("Remote: %s is now %s ****" % (self.hostname, RemoteStatus(self.status).name))
            self.emit("remote-status-changed")

        return GLib.SOURCE_REMOVE

    def emit_machine_info_changed(self):
        with self.machine_info_changed_lock:
            if self.machine_info_changed_source_id > 0:
                GLib.source_remove(self.machine_info_changed_source_id)

            self.machine_info_changed_source_id = GLib.idle_add(self.emit_machine_info_changed_cb)

    def emit_machine_info_changed_cb(self):
        with self.machine_info_changed_lock:
            self.machine_info_changed_source_id = 0
            self.emit("machine-info-changed")

        return GLib.SOURCE_REMOVE

    def rpc_call(self, coro_func, *args, **kargs):
        # Replacement for the old global thread pool submit. Schedule a coroutine
        # on the asyncio loop. Caller must pass an `async def` callable.
        try:
            asyncio.create_task(coro_func(*args, **kargs))
        except Exception as e:
            logging.critical("!! Failed to schedule call to %s (%s:%d): %s"
                                 % (self.display_hostname, self.ip_info, self.port, e))

    async def check_duplex_connection(self):
        logging.debug("Remote: checking duplex with '%s'" % self.display_hostname)

        ret = await self.stub.CheckDuplexConnection(
            warp_pb2.LookupName(id=self.local_ident, readable_name=util.get_hostname())
        )

        return ret.response

    async def wait_for_duplex(self):
        logging.debug("Remote: waiting for duplex from '%s'" % self.display_hostname)

        return await self.stub.WaitingForDuplex(
            warp_pb2.LookupName(id=self.local_ident, readable_name=util.get_hostname())
        )

    async def update_remote_machine_info(self):
        logging.debug("Remote RPC: calling GetRemoteMachineInfo on '%s'" % self.display_hostname)
        try:
            info = await self.stub.GetRemoteMachineInfo(
                warp_pb2.LookupName(id=self.local_ident, readable_name=util.get_hostname())
            )
        except grpc.aio.AioRpcError as e:
            logging.debug("Remote RPC: GetRemoteMachineInfo failed for '%s': %s" % (self.display_hostname, e))
            return

        self.display_name = info.display_name
        self.user_name = info.user_name
        feature_flags = RemoteFeatures(info.feature_flags)
        self.supports_messages = RemoteFeatures.TEXT_MESSAGES in feature_flags
        self.favorite = prefs.get_is_favorite(self.ident)

        valid = GLib.utf8_make_valid(self.display_name, -1)
        self.sort_key = GLib.utf8_collate_key(valid.lower(), -1)

        self.emit_machine_info_changed()
        self.set_remote_status(RemoteStatus.ONLINE)

    async def update_remote_machine_avatar(self):
        logging.debug("Remote RPC: calling GetRemoteMachineAvatar on '%s'" % self.display_hostname)
        loader = None
        try:
            call = self.stub.GetRemoteMachineAvatar(
                warp_pb2.LookupName(id=self.local_ident, readable_name=util.get_hostname())
            )
            async for info in call:
                if loader is None:
                    loader = util.CairoSurfaceLoader()
                loader.add_bytes(info.avatar_chunk)
        except grpc.aio.AioRpcError as e:
            logging.debug("Remote RPC: could not fetch remote avatar, using a generic one. (%s, %s)" % (e.code(), e.details()))

        self.get_avatar_surface(loader)

    @misc._idle
    def get_avatar_surface(self, loader=None):
        if loader:
            self.avatar_surface = loader.get_surface()
        else:
            self.avatar_surface = None

        self.emit_machine_info_changed()

    async def send_transfer_op_request(self, op):
        if not self.stub:
            return

        logging.debug("Remote RPC: calling TransferOpRequest on '%s'" % (self.display_hostname))

        transfer_op = warp_pb2.TransferOpRequest(
            info=warp_pb2.OpInfo(
                ident=op.sender,
                timestamp=op.start_time,
                readable_name=util.get_hostname(),
                use_compression=prefs.use_compression(),
            ),
            sender_name=op.sender_name,
            receiver=self.ident,
            size=op.total_size,
            count=op.total_count,
            name_if_single=op.description,
            mime_if_single=op.mime_if_single,
            top_dir_basenames=op.top_dir_basenames
        )

        await self.stub.ProcessTransferOpRequest(transfer_op)

    async def cancel_transfer_op_request(self, op, by_sender=False):
        logging.debug("Remote RPC: calling CancelTransferOpRequest on '%s'" % (self.display_hostname))

        if op.direction == TransferDirection.TO_REMOTE_MACHINE:
            name = op.sender
        else:
            name = self.local_ident
        await self.stub.CancelTransferOpRequest(
            warp_pb2.OpInfo(
                timestamp=op.start_time,
                ident=name,
                readable_name=util.get_hostname()
            )
        )
        op.set_status(OpStatus.CANCELLED_PERMISSION_BY_SENDER if by_sender else OpStatus.CANCELLED_PERMISSION_BY_RECEIVER)

    async def start_transfer_op(self, op):
        logging.debug("Remote RPC: calling StartTransfer on '%s'" % (self.display_hostname))

        start_time = GLib.get_monotonic_time()

        op.progress_tracker = transfers.OpProgressTracker(op)
        op.current_progress_report = None
        receiver = transfers.FileReceiver(op)
        op.set_status(OpStatus.TRANSFERRING)

        # Per-op single-worker executor: a fresh thread for this receive op,
        # landlocked to the save path on first use, terminates with shutdown().
        executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="recv-op-%d" % op.start_time,
        )
        loop = asyncio.get_event_loop()

        op.file_iterator = self.stub.StartTransfer(
            warp_pb2.OpInfo(
                timestamp=op.start_time,
                ident=self.local_ident,
                readable_name=util.get_hostname(),
                use_compression=op.use_compression and prefs.use_compression()
            )
        )

        async def report_receive_error(error):
            op.file_iterator = None

            await loop.run_in_executor(executor, receiver.clean_current_top_dir_file)

            if error is None:
                return

            op.set_error(error)

            if receiver.current_stream is not None:
                try:
                    await loop.run_in_executor(executor, receiver.current_stream.close)
                except GLib.Error:
                    pass

            logging.critical("An error occurred receiving data from %s: %s" % (op.sender, op.error_msg))
            op.set_status(OpStatus.FAILED)
            op.stop_transfer()

        try:
            # Apply landlock once on the worker thread.
            await loop.run_in_executor(executor, receiver.apply_landlock)
            await loop.run_in_executor(executor, receiver.clean_existing_files)

            async for data in op.file_iterator:
                await loop.run_in_executor(executor, receiver.receive_data, data)

            op.file_iterator = None
            await loop.run_in_executor(executor, receiver.receive_finished)

            logging.debug("Remote: receipt of %s files (%s) finished in %s" %
                          (op.total_count, GLib.format_size(op.total_size),
                           util.precise_format_time_span(GLib.get_monotonic_time() - start_time)))

            if op.remaining_count > 0:
                raise ReceiveError(
                    "Transfer completed, but the number of files received is less than the original request size (expected %d, received %d)"
                        % (op.total_count, op.total_count - op.remaining_count),
                    fatal=False)
            op.set_status(OpStatus.FINISHED)
        except grpc.aio.AioRpcError as e:
            if e.code() == grpc.StatusCode.CANCELLED:
                await report_receive_error(None)
            else:
                await report_receive_error(e)
        except ReceiveError as e:
            if e.fatal:
                await report_receive_error(e)
            else:
                logging.critical(str(e))
                op.set_error(e)
                op.set_status(OpStatus.FINISHED_WARNING)
        except Exception as e:
            await report_receive_error(e)
        finally:
            executor.shutdown(wait=True)

    async def stop_transfer_op(self, op, by_sender=False, lost_connection=False):
        logging.debug("Remote RPC: Calling StopTransfer on '%s'" % (self.display_hostname))

        if op.direction == TransferDirection.TO_REMOTE_MACHINE:
            name = op.sender
        else:
            name = self.local_ident

        if by_sender:
            op.file_send_cancellable.set()
            if not lost_connection:
                logging.debug("Remote: stop transfer initiated by sender")
                if op.error_msg == "":
                    op.set_status(OpStatus.STOPPED_BY_SENDER)
                else:
                    op.set_status(OpStatus.FAILED)
        else:
            if op.file_iterator:
                op.file_iterator.cancel()
            if not lost_connection:
                logging.debug("Remote: stop transfer initiated by receiver")
                if op.error_msg == "":
                    op.set_status(OpStatus.STOPPED_BY_RECEIVER)
                else:
                    op.set_status(OpStatus.FAILED)

        if not lost_connection:
            opinfo = warp_pb2.OpInfo(
                timestamp=op.start_time,
                ident=name,
                readable_name=util.get_hostname()
            )
            try:
                await self.stub.StopTransfer(warp_pb2.StopInfo(info=opinfo, error=op.error_msg != ""))
            except grpc.aio.AioRpcError as e:
                logging.debug("Remote: StopTransfer RPC failed (peer may have already stopped): %s" % e)

    def send_files(self, uri_list, dbus_sent=False):
        async def _send_files():
            op = SendOp(
                self.local_ident,
                self.ident,
                self.display_name,
                uri_list
            )
            op.dbus_op = dbus_sent
            self.add_op(op)
            await asyncio.to_thread(op.prepare_send_info)

        util.add_to_recents_if_single_selection(uri_list)
        self.rpc_call(_send_files)

    def send_text_message(self, message):
        op = TextMessageOp(TransferDirection.TO_REMOTE_MACHINE, self.local_ident)
        op.message = message
        op.status = OpStatus.FINISHED
        self.add_op(op)
        self.rpc_call(self.do_send_text_message, op)

    async def do_send_text_message(self, op):
        try:
            await self.stub.SendTextMessage(warp_pb2.TextMessage(ident=self.local_ident, timestamp=op.start_time, message=op.message))
        except Exception as e:
            logging.error("Sending message failed: %s" % e)
            op.status = OpStatus.FAILED
            op.emit_status_changed()

    @misc._idle
    def add_op(self, op):
        if op not in self.transfer_ops:
            self.transfer_ops.append(op)
            op.connect("status-changed", self.emit_ops_changed)
            op.connect("op-command", self.op_command_issued)
            op.connect("focus", self.op_focus)
            if isinstance(op, SendOp):
                op.connect("initial-setup-complete", self.notify_remote_machine_of_new_op)
                self.emit("new-outgoing-op", op)
            if isinstance(op, (ReceiveOp, TextMessageOp)):
                self.emit("new-incoming-op", op)

        def set_busy():
            self.busy = True

        op.connect("active", lambda op: set_busy())

        self.emit_ops_changed()

        # For now, only bad base filenames cause this (failed util.test_resolved_path_safety())
        # We let it get this far so the UI has something to show the user.
        if op.status == OpStatus.FAILED_UNRECOVERABLE:
            op.decline_transfer_request()
            return

        self.check_for_autostart(op)

    @misc._idle
    def notify_remote_machine_of_new_op(self, op):
        if op.status == OpStatus.WAITING_PERMISSION:
            if op.direction == TransferDirection.TO_REMOTE_MACHINE:
                self.rpc_call(self.send_transfer_op_request, op)

    @misc._idle
    def check_for_autostart(self, op):
        if op.status == OpStatus.WAITING_PERMISSION:
            if isinstance(op, ReceiveOp) and \
              op.have_space and \
              (not (op.existing and prefs.prevent_overwriting())) and \
              (not prefs.require_permission_for_transfer()):
                op.accept_transfer()

    def remove_op(self, op):
        self.transfer_ops.remove(op)
        self.emit_ops_changed()

    @misc._idle
    def emit_ops_changed(self, op=None):
        self.emit("ops-changed")

    def cancel_ops_if_offline(self):
        if self.status in (RemoteStatus.OFFLINE, RemoteStatus.UNREACHABLE):
            for op in self.transfer_ops:
                if op.status == OpStatus.TRANSFERRING:
                    op.error_msg = _("Connection has been lost")
                    self.rpc_call(self.stop_transfer_op, op, isinstance(op, SendOp), lost_connection=True)
                    op.set_status(OpStatus.FAILED)
                elif op.status in (OpStatus.WAITING_PERMISSION, OpStatus.CALCULATING, OpStatus.PAUSED):
                    op.error_msg = _("Connection has been lost")
                    op.set_status(OpStatus.FAILED_UNRECOVERABLE)

    @misc._idle
    def op_command_issued(self, op, command):
        # send
        if command == OpCommand.CANCEL_PERMISSION_BY_SENDER:
            self.rpc_call(self.cancel_transfer_op_request, op, by_sender=True)
        elif command == OpCommand.STOP_TRANSFER_BY_SENDER:
            self.rpc_call(self.stop_transfer_op, op, by_sender=True)
        elif command == OpCommand.RETRY_TRANSFER:
            if isinstance(op, TextMessageOp):
                op.status = OpStatus.FINISHED
                op.emit_status_changed()
                self.rpc_call(self.do_send_text_message, op)
            else:
                op.set_status(OpStatus.WAITING_PERMISSION)
                self.rpc_call(self.send_transfer_op_request, op)
        elif command == OpCommand.REMOVE_TRANSFER:
            self.remove_op(op)
        # receive
        elif command == OpCommand.START_TRANSFER:
            self.rpc_call(self.start_transfer_op, op)
        elif command == OpCommand.CANCEL_PERMISSION_BY_RECEIVER:
            self.rpc_call(self.cancel_transfer_op_request, op, by_sender=False)
        elif command == OpCommand.STOP_TRANSFER_BY_RECEIVER:
            self.rpc_call(self.stop_transfer_op, op, by_sender=False)

    @misc._idle
    def op_focus(self, op):
        self.emit("focus-remote")

    def lookup_op(self, timestamp):
        for op in self.transfer_ops:
            if op.start_time == timestamp:
                return op
