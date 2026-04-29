#!/usr/bin/python3

import asyncio
import logging
import threading
import socket

import grpc
import grpc.aio
import warp_pb2_grpc
import warp_pb2

import auth
import util
import prefs
import config


class RegRequest():
    def __init__(self, ident, hostname, ip_info, port, auth_port, api_version):
        self.api_version = api_version
        self.ident = ident
        self.hostname = hostname
        self.ip_info = ip_info
        self.port = port

        # v1 only
        self.request = None

        # v2 only
        self.auth_port = auth_port
        self.locked_cert = None

        self.cancelled = False

    def cancel(self):
        self.cancelled = True


class Registrar():
    def __init__(self, ip_info, port, auth_port, loop):
        self.reg_server_v1 = None
        self.reg_server_v2 = None
        self.active_registrations = {}
        self.reg_lock = threading.Lock()

        self.ip_info = ip_info
        self.port = port
        self.auth_port = auth_port
        self._loop = loop

        # v1 is UDP sockets in threads; spin up immediately.
        # v2 is grpc.aio; instantiate now (no I/O), the caller awaits start().
        logging.debug("Starting v1 registration server (%s) with port %d" % (self.ip_info, self.port))
        self.reg_server_v1 = RegistrationServer_v1(self.ip_info, self.port)
        logging.debug("Starting v2 registration server (%s) with auth port %d" % (self.ip_info, self.auth_port))
        self.reg_server_v2 = RegistrationServer_v2(self.ip_info, self.auth_port)

    async def start(self):
        await self.reg_server_v2.start()

    async def shutdown_registration_servers(self):
        with self.reg_lock:
            for key in self.active_registrations.keys():
                self.active_registrations[key].cancel()
            self.active_registrations = {}

        if self.reg_server_v1 is not None:
            logging.debug("Stopping v1 registration server.")
            self.reg_server_v1.stop()
            self.reg_server_v1 = None

        if self.reg_server_v2 is not None:
            logging.debug("Stopping v2 registration server.")
            await self.reg_server_v2.stop()
            self.reg_server_v2 = None

    async def register_async(self, ident, hostname, ip_info, port, auth_port, api_version):
        # Async core. Callable directly from coroutines on self._loop.
        details = RegRequest(ident, hostname, ip_info, port, auth_port, api_version)
        with self.reg_lock:
            self.active_registrations[ident] = details

        ret = None

        try:
            if api_version == "1":
                # v1 cert exchange is blocking UDP socket I/O.
                ret = await asyncio.to_thread(register_v1, details)
            elif api_version == "2":
                ret = await register_v2(details)
        finally:
            with self.reg_lock:
                try:
                    del self.active_registrations[ident]
                except KeyError:
                    pass

        return ret

    def register(self, ident, hostname, ip_info, port, auth_port, api_version):
        # Sync entry point for foreign-thread callers (kept as a convenience).
        # Loop-thread callers must use register_async() to avoid deadlocking on
        # run_coroutine_threadsafe(...).result().
        future = asyncio.run_coroutine_threadsafe(
            self.register_async(ident, hostname, ip_info, port, auth_port, api_version),
            self._loop,
        )
        try:
            return future.result()
        except Exception as e:
            logging.critical("Registrar.register: coroutine failed: %s" % e)
            return util.CertProcessingResult.FAILURE


# ====================== api v1 ======================

def register_v1(details):
    # This will block if the remote's warp udp port is closed, until either the port is unblocked
    # or we tell the auth object to shutdown, in which case the request timer will cancel and return
    # here immediately (with None)

    logging.debug("Registering with %s (%s:%d) - api version 1" % (details.hostname, details.ip_info, details.port))

    success = retrieve_remote_cert(details)

    if success == util.CertProcessingResult.FAILURE:
        logging.debug("Unable to register with %s (%s:%d) - api version 1"
                             % (details.hostname, details.ip_info, details.port))
        return False

    return True


def retrieve_remote_cert(details):
    logging.debug("Auth: Starting a new RequestLoop for '%s' (%s:%d)" % (details.hostname, details.ip_info, details.port))

    details.request = Request(details.ip_info, details.port)
    data = details.request.request()

    if data is None or details.cancelled:
        return util.CertProcessingResult.FAILURE

    return auth.get_singleton().process_remote_cert(details.hostname,
                                                    details.ip_info,
                                                    data)


REQUEST = b"REQUEST"


# v1 client
class Request():
    def __init__(self, ip_info, port):
        self.ip_info = ip_info
        self.port = port

    def request(self):
        logging.debug("Auth: Requesting cert from remote (%s:%d)" % (self.ip_info, self.port))

        remote_ip, _, ip_version = self.ip_info.get_usable_ip()

        try:
            ip = remote_ip if ip_version == socket.AF_INET else "[%s]" % (remote_ip,)
            server_sock = socket.socket(ip_version, socket.SOCK_DGRAM)
            server_sock.settimeout(5.0)
            server_sock.sendto(REQUEST, (ip, self.port))

            reply, addr = server_sock.recvfrom(2000)

            if addr == (remote_ip, self.port):
                return reply
        except socket.timeout:
            logging.debug("Auth: Cert request failed from remote (%s:%d) - (Is their udp port blocked?"
                              % (self.ip_info, self.port))
        except socket.error as e:
            logging.critical("Something wrong with cert request (%s:%s): " % (remote_ip, self.port, e))

        return None


# v1 server
class RegistrationServer_v1():
    def __init__(self, ip_info, port):
        self.exit = False
        self.ip_info = ip_info
        self.port = port

        self.thread4 = threading.Thread(target=self.serve_cert_thread, args=(socket.AF_INET,))
        self.thread6 = threading.Thread(target=self.serve_cert_thread, args=(socket.AF_INET6,))
        self.thread4.start()
        self.thread6.start()

    def serve_cert_thread(self, ip_version):
        local_ip = None
        if ip_version == socket.AF_INET:
            local_ip = self.ip_info.ip4_address
        elif ip_version == socket.AF_INET6:
            local_ip = self.ip_info.ip6_address

        if local_ip is not None:
            try:
                server_sock = socket.socket(ip_version, socket.SOCK_DGRAM)
                server_sock.settimeout(1.0)
                server_sock.bind((local_ip, self.port))
            except socket.error as e:
                logging.critical("Could not create udp socket for cert requests: %s" % str(e))
                return

            while True:
                try:
                    data, address = server_sock.recvfrom(2000)

                    if data == REQUEST:
                        cert_data = auth.get_singleton().get_encoded_local_cert()
                        server_sock.sendto(cert_data, address)
                except socket.timeout:
                    if self.exit:
                        server_sock.close()
                        break

    def stop(self):
        self.exit = True
        self.thread4.join()
        self.thread6.join()


# ====================== api v2 ======================

async def register_v2(details):
    logging.debug("Registering with %s (%s:%d) - api version 2" % (details.hostname, details.ip_info, details.auth_port))

    await register_with_remote(details)

    success = None
    if details.locked_cert is not None and not details.cancelled:
        success = auth.get_singleton().process_remote_cert(details.hostname,
                                                           details.ip_info,
                                                           details.locked_cert)

    if success == util.CertProcessingResult.FAILURE:
        logging.debug("Unable to register with %s (%s:%d) - api version 2"
                             % (details.hostname, details.ip_info, details.auth_port))
    elif success == util.CertProcessingResult.CERT_INSERTED:
        logging.debug("Successfully registered with %s (%s:%d) - api version 2"
                             % (details.hostname, details.ip_info, details.auth_port))
    elif success == util.CertProcessingResult.CERT_UPDATED:
        logging.debug("Successfully updated registration with %s (%s:%d) - api version 2"
                             % (details.hostname, details.ip_info, details.auth_port))
    elif success == util.CertProcessingResult.CERT_UP_TO_DATE:
        logging.debug("Certificate already up to date, nothing to do for %s (%s:%d) - api version 2"
                             % (details.hostname, details.ip_info, details.auth_port))
    return success


async def register_with_remote(details):
    logging.debug("Remote: Attempting to register %s (%s)" % (details.hostname, details.ip_info))

    remote_ip, local_ip, ip_version = details.ip_info.get_usable_ip()
    remote_ip = remote_ip if ip_version == socket.AF_INET else "[%s]" % (remote_ip,)

    async with grpc.aio.insecure_channel("%s:%d" % (remote_ip, details.auth_port)) as channel:
        try:
            stub = warp_pb2_grpc.WarpRegistrationStub(channel)
            ret = await asyncio.wait_for(
                stub.RequestCertificate(warp_pb2.RegRequest(ip=remote_ip, hostname=util.get_hostname())),
                timeout=5,
            )
            details.locked_cert = ret.locked_cert.encode("utf-8")
        except Exception as e:
            logging.critical("Problem with remote registration: %s (%s:%d) - api version 2: %s"
                     % (details.hostname, details.ip_info, details.auth_port, e))


class RegistrationServer_v2():
    def __init__(self, ip_info, auth_port):
        self.ip_info = ip_info
        self.auth_port = auth_port

        self.server = None
        self.service_registration_handler = None

    async def start(self):
        self.server = grpc.aio.server()
        warp_pb2_grpc.add_WarpRegistrationServicer_to_server(self, self.server)

        if self.ip_info.ip4_address is not None:
            self.server.add_insecure_port('%s:%d' % (self.ip_info.ip4_address, self.auth_port))
        if self.ip_info.ip6_address is not None:
            self.server.add_insecure_port('[%s]:%d' % (self.ip_info.ip6_address, self.auth_port))

        await self.server.start()

    async def stop(self):
        if self.server is not None:
            logging.debug("Registration Server v2 stopping")
            await self.server.stop(grace=2)
            logging.debug("Registration Server v2 stopped")
            self.server = None

    async def RequestCertificate(self, request, context):
        logging.debug("Registration Server RPC: RequestCertificate from %s '%s'" % (request.hostname, request.ip))

        return warp_pb2.RegResponse(locked_cert=auth.get_singleton().get_encoded_local_cert())

    async def RegisterService(self, reg: warp_pb2.ServiceRegistration, context):
        logging.debug("Received manual registration from " + reg.service_id)
        if self.service_registration_handler is not None:
            await self.service_registration_handler(reg)
        return warp_pb2.ServiceRegistration(service_id=prefs.get_connect_id(),
                                            ip=self.ip_info.ip4_address,
                                            port=prefs.get_port(),
                                            hostname=util.get_hostname(),
                                            api_version=int(config.RPC_API_VERSION),
                                            auth_port=self.auth_port,
                                            ipv6=self.ip_info.ip6_address)
