import socket
import time
import os
import threading
import gettext
from concurrent import futures

from gi.repository import GObject, GLib
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser

import grpc
import warp_pb2
import warp_pb2_grpc

import prefs
import util
import transfers
from ops import SendOp, ReceiveOp
from util import TransferDirection, OpStatus, OpCommand, RemoteStatus

_ = gettext.gettext

#typedef
void = warp_pb2.VoidType()

MAX_CONNECT_RETRIES = 2
PING_TIME = 5

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

    def __init__(self, name, hostname, ip, port, local_service_name):
        GObject.Object.__init__(self)
        self.ip_address = ip
        self.port = port
        self.connect_name = name
        self.hostname = hostname
        self.user_name = ""
        self.display_name = ""
        self.favorite = prefs.get_is_favorite(self.hostname)
        self.recent_time = 0 # Keep monotonic time when visited on the user page
        self.status = RemoteStatus.INIT_CONNECTING
        self.avatar_surface = None
        self.transfer_ops = []

        self.stub = None

        self.changed_source_id = 0

        self.need_shutdown = False
        self.connect_loop_cancelled = True

        self.sort_key = self.hostname
        self.local_service_name = local_service_name

        prefs.prefs_settings.connect("changed::favorites", self.update_favorite_status)

    @util._async
    def start(self):
        self.need_shutdown = False
        self.connect_loop_cancelled = False

        print("Connecting to %s" % self.connect_name)
        self.set_remote_status(RemoteStatus.INIT_CONNECTING)

        def keep_channel():
            creds = None
            with open('/home/mtwebster/.ssh/id_rsa.pub', 'rb') as f:
                creds = grpc.ssl_channel_credentials(f.read())

            with grpc.secure_channel("%s:%d" % (self.ip_address, self.port), creds) as channel:
                future = grpc.channel_ready_future(channel)

                connect_retries = 0

                while not self.need_shutdown:
                    try:
                        future.result(timeout=2)
                        self.stub = warp_pb2_grpc.WarpStub(channel)
                        break
                    except grpc.FutureTimeoutError:
                        if connect_retries < MAX_CONNECT_RETRIES:
                            print("channel ready timeout, waiting 10s")
                            time.sleep(PING_TIME)
                            connect_retries += 1
                            continue
                        else:
                            self.set_remote_status(RemoteStatus.UNREACHABLE)
                            print("Trying to remake channel")
                            return True

                one_ping = False
                while not self.need_shutdown:
                    try:
                        self.stub.Ping(void, timeout=2)
                        self.set_remote_status(RemoteStatus.ONLINE)
                        if not one_ping:
                            self.update_remote_machine_info()
                            self.update_remote_machine_avatar()
                            one_ping = True
                    except grpc.RpcError as e:
                        if e.code() in (grpc.StatusCode.DEADLINE_EXCEEDED, grpc.StatusCode.UNAVAILABLE):
                            one_ping = False
                            self.set_remote_status(RemoteStatus.UNREACHABLE)

                    time.sleep(PING_TIME)
                return False

        while keep_channel():
            continue

    @util._async
    def update_remote_machine_info(self):
        def get_info_finished(future):
            info = future.result()
            self.display_name = info.display_name
            self.user_name = info.user_name
            self.favorite = prefs.get_is_favorite(self.hostname)

            valid = GLib.utf8_make_valid(self.display_name, -1)
            self.sort_key = GLib.utf8_collate_key(valid.lower(), -1)

            self.emit_machine_info_changed()
            self.set_remote_status(RemoteStatus.ONLINE)
        
        future = self.stub.GetRemoteMachineInfo.future(void)
        future.add_done_callback(get_info_finished)

    @util._async
    def update_remote_machine_avatar(self):
        iterator = self.stub.GetRemoteMachineAvatar(void)
        loader = None
        try:
            for info in iterator:
                if loader == None:
                    loader = util.CairoSurfaceLoader()
                loader.add_bytes(info.avatar_chunk)
        except grpc.RpcError as e:
            print("Could not fetch remote avatar, using a generic one. (%s, %s)" % (e.code(), e.details()))

        self.get_avatar_surface(loader)

    @util._idle
    def get_avatar_surface(self, loader=None):
        # This needs to be on the main loop, or else we get an x error
        if loader:
            self.avatar_surface = loader.get_surface()
        else:
            self.avatar_surface = None

        self.emit_machine_info_changed()

    @util._async
    def send_transfer_op_request(self, op):
        if not self.stub: # short circuit for testing widgets
            return

        transfer_op = warp_pb2.TransferOpRequest(info=warp_pb2.OpInfo(connect_name=op.sender,
                                                                      timestamp=op.start_time),
                                                 sender_name=op.sender_name,
                                                 receiver=self.connect_name,
                                                 size=op.total_size,
                                                 count=op.total_count,
                                                 name_if_single=op.description,
                                                 mime_if_single=op.mime_if_single,
                                                 top_dir_basenames=op.top_dir_basenames)

        self.stub.ProcessTransferOpRequest(transfer_op)

    @util._async
    def cancel_transfer_op_request(self, op, by_sender=False):
        if op.direction == TransferDirection.TO_REMOTE_MACHINE:
            name = op.sender
        else:
            name = self.local_service_name
        self.stub.CancelTransferOpRequest(warp_pb2.OpInfo(timestamp=op.start_time,
                                                          connect_name=name))
        op.set_status(OpStatus.CANCELLED_PERMISSION_BY_SENDER if by_sender else OpStatus.CANCELLED_PERMISSION_BY_RECEIVER)

    # def pause_transfer_op(self, op):
        # stop_op = warp_pb2.PauseTransferOp(warp_pb2.OpInfo(timestamp=op.start_time))
        # self.emit("ops-changed")

    #### RECEIVER COMMANDS ####
    @util._async
    def start_transfer_op(self, op):
        start_time = GLib.get_monotonic_time()

        op.progress_tracker = transfers.OpProgressTracker(op)
        op.current_progress_report = None
        receiver = transfers.FileReceiver(op)
        op.set_status(OpStatus.TRANSFERRING)

        op.file_iterator = self.stub.StartTransfer(warp_pb2.OpInfo(timestamp=op.start_time,
                                                                   connect_name=self.local_service_name))

        def report_receive_error(error):
            op.set_error(error)

            try:
                # If we leave an io stream open, it locks the location.  For instance,
                # if this was a mounted location, we wouldn't be able to terminate until
                # we closed warp.
                receiver.current_stream.close()
            except GLib.Error:
                pass

            print("An error occurred receiving data from %s: %s" % (op.sender, op.error_msg))
            op.set_status(OpStatus.FAILED)
            op.stop_transfer()

        try:
            for data in op.file_iterator:
                receiver.receive_data(data)
        except grpc.RpcError:
            if op.file_iterator.code() == grpc.StatusCode.CANCELLED:
                op.file_iterator = None
                return
            else:
                report_receive_error(op.file_iterator)
                return
        except Exception as e:
            report_receive_error(e)
            return

        op.file_iterator = None
        receiver.receive_finished()

        print("Receipt of %s files (%s) finished in %s" % \
              (op.total_count, GLib.format_size(op.total_size),\
               util.precise_format_time_span(GLib.get_monotonic_time() - start_time)))

        op.set_status(OpStatus.FINISHED)

    @util._async
    def stop_transfer_op(self, op, by_sender=False, lost_connection=False):
        if op.direction == TransferDirection.TO_REMOTE_MACHINE:
            name = op.sender
        else:
            name = self.local_service_name

        if by_sender:
            op.file_send_cancellable.set()
            # If we stopped due to connection error, we don't want the message to be 'stopped by xx',
            # but just failed.
            if not lost_connection:
                print("stop transfer initiated by sender")
                if op.error_msg == "":
                    op.set_status(OpStatus.STOPPED_BY_SENDER)
                else:
                    op.set_status(OpStatus.FAILED)
        else:
            op.file_iterator.cancel()
            if not lost_connection:
                print("stop transfer initiated by receiver")
                if op.error_msg == "":
                    op.set_status(OpStatus.STOPPED_BY_RECEIVER)
                else:
                    op.set_status(OpStatus.FAILED)

        if not lost_connection:
            # We don't need to send this if it's a connection loss, the other end will handle
            # its own cleanup.
            opinfo = warp_pb2.OpInfo(timestamp=op.start_time,
                                     connect_name=name)
            self.stub.StopTransfer(warp_pb2.StopInfo(info=opinfo, error=op.error_msg != ""))

    @util._async
    def send_files(self, uri_list):
        op = SendOp(self.local_service_name,
                    self.connect_name,
                    self.display_name,
                    uri_list)
        self.add_op(op)
        op.prepare_send_info()

    def update_favorite_status(self, pspec, data=None):
        old_favorite = self.favorite
        self.favorite = prefs.get_is_favorite(self.hostname)

        if old_favorite != self.favorite:
            self.emit_machine_info_changed()

    def stamp_recent_time(self):
        self.recent_time = GLib.get_monotonic_time()
        self.emit_machine_info_changed()

    @util._idle
    def notify_remote_machine_of_new_op(self, op):
        if op.status == OpStatus.WAITING_PERMISSION:
            if op.direction == TransferDirection.TO_REMOTE_MACHINE:
                self.send_transfer_op_request(op)

    @util._idle
    def add_op(self, op):
        if op not in self.transfer_ops:
            self.transfer_ops.append(op)
            op.connect("status-changed", self.emit_ops_changed)
            op.connect("op-command", self.op_command_issued)
            op.connect("focus", self.op_focus)
            if isinstance(op, SendOp):
                op.connect("initial-setup-complete", self.notify_remote_machine_of_new_op)
                self.emit("new-outgoing-op", op)
            if isinstance(op, ReceiveOp):
                self.emit("new-incoming-op", op)
        self.emit_ops_changed()
        self.check_for_autostart(op)

    @util._idle
    def check_for_autostart(self, op):
        if op.status == OpStatus.WAITING_PERMISSION:
            if isinstance(op, ReceiveOp) and \
              op.have_space  and not op.existing and (not prefs.require_permission_for_transfer()):
                op.accept_transfer()

    @util._idle
    def remove_op(self, op):
        self.transfer_ops.remove(op)
        self.emit_ops_changed()

    @util._idle
    def emit_ops_changed(self, op=None):
        self.emit("ops-changed")

    @util._idle
    def set_remote_status(self, status):
        if status == self.status:
            return

        self.status = status
        self.cancel_ops_if_offline()
        self.emit("remote-status-changed")

    def cancel_ops_if_offline(self):
        if self.status in (RemoteStatus.OFFLINE, RemoteStatus.UNREACHABLE):
            for op in self.transfer_ops:
                if op.status == OpStatus.TRANSFERRING:
                    op.error_msg = _("Connection has been lost")
                    self.stop_transfer_op(op, isinstance(op, SendOp), lost_connection=True)
                    op.set_status(OpStatus.FAILED)
                elif op.status in (OpStatus.WAITING_PERMISSION, OpStatus.CALCULATING, OpStatus.PAUSED):
                    op.error_msg = _("Connection has been lost")
                    op.set_status(OpStatus.FAILED_UNRECOVERABLE)

    @util._idle
    def op_command_issued(self, op, command):
        # send
        if command == OpCommand.CANCEL_PERMISSION_BY_SENDER:
            self.cancel_transfer_op_request(op, by_sender=True)
        elif command == OpCommand.PAUSE_TRANSFER:
            self.pause_transfer_op(op)
        elif command == OpCommand.STOP_TRANSFER_BY_SENDER:
            self.stop_transfer_op(op, by_sender=True)
        elif command == OpCommand.RETRY_TRANSFER:
            op.set_status(OpStatus.WAITING_PERMISSION)
            self.send_transfer_op_request(op)
        elif command == OpCommand.REMOVE_TRANSFER:
            self.remove_op(op)
        # receive
        elif command == OpCommand.START_TRANSFER:
            self.start_transfer_op(op)
        elif command == OpCommand.CANCEL_PERMISSION_BY_RECEIVER:
            self.cancel_transfer_op_request(op, by_sender=False)
        elif command == OpCommand.STOP_TRANSFER_BY_RECEIVER:
            self.stop_transfer_op(op, by_sender=False)

    @util._idle
    def op_focus(self, op):
        self.emit("focus-remote")

    def emit_machine_info_changed(self):
        if self.changed_source_id > 0:
            GLib.source_remove(self.changed_source_id)

        self.changed_source_id = GLib.idle_add(self.emit_machine_info_changed_cb)

    def emit_machine_info_changed_cb(self):
        self.emit("machine-info-changed")
        self.changed_source_id = 0
        return False

    def lookup_op(self, timestamp):
        for op in self.transfer_ops:
            if op.start_time == timestamp:
                return op

    def shutdown(self):
        print("Shutdown - closing connection to remote machine '%s'" % self.connect_name)
        self.set_remote_status(RemoteStatus.OFFLINE)
        self.need_shutdown = True
        while not self.connect_loop_cancelled:
            time.sleep(1)

# server
class LocalMachine(warp_pb2_grpc.WarpServicer, GObject.Object):
    __gsignals__ = {
        "remote-machine-added": (GObject.SignalFlags.RUN_LAST, None, (object,)),
        "remote-machine-removed": (GObject.SignalFlags.RUN_LAST, None, (object,)),
        "remote-machine-ops-changed": (GObject.SignalFlags.RUN_LAST, None, (str,)),
        "server-started": (GObject.SignalFlags.RUN_LAST, None, ()),
        "shutdown-complete": (GObject.SignalFlags.RUN_LAST, None, ())
    }
    def __init__(self):
        self.service_name = "warp.__%s__.__%s__._http._tcp.local." % (util.get_ip(), util.get_hostname())
        super(LocalMachine, self).__init__()
        GObject.Object.__init__(self)

        self.ip_address = util.get_ip()
        self.port = prefs.get_port()

        self.remote_machines = {}
        self.server_runlock = threading.Condition()

        self.browser = None
        self.zeroconf = None
        self.zeroconf = None
        self.info = None

        self.display_name = GLib.get_real_name()

        self.start_server()

    def start_zeroconf(self):
        self.zeroconf = Zeroconf()
        self.info = ServiceInfo("_http._tcp.local.",
                                self.service_name,
                                socket.inet_aton(util.get_ip()), prefs.get_port(), 0, 0,
                                {}, "somehost.local.")
        self.zeroconf.register_service(self.info)

    def start_remote_lookout(self):
        print("Searching for others...")
        self.browser = ServiceBrowser(self.zeroconf, "_http._tcp.local.", self)

    @util._async
    def remove_service(self, zeroconf, _type, name):
        if name == self.service_name or not name.count("warp"):
            return

        print("Service %s removed" % (name,))

        try:
            self.emit_remote_machine_removed(self.remote_machines[name])
            self.remote_machines[name].shutdown()
            # del self.remote_machines[name]
            print("Removing remote machine '%s'" % name)
        except KeyError:
            print("Removed client we never knew: %s" % name)

    @util._async
    def add_service(self, zeroconf, _type, name):
        info = zeroconf.get_service_info(_type, name)

        if info and name.count("warp"):
            if name == self.service_name:
                return

            # zeroconf service info might have multiple ip addresses, extract it from their 'name',
            # as well as the hostname, since we want to display it whether we get a connection or not.
            remote_ip, remote_hostname = name.replace("warp.__", "").replace("__._http._tcp.local.", "").split("__.__")
            print("Client %s added at %s" % (name, remote_ip))

            try:
                machine = self.remote_machines[name]
                machine.port = info.port
            except KeyError:
                machine = RemoteMachine(name, remote_hostname, remote_ip, info.port, self.service_name)
                self.remote_machines[name] = machine
                machine.connect("ops-changed", self.remote_ops_changed)
                self.emit_remote_machine_added(machine)

            machine.start()

    @util._idle
    def emit_remote_machine_added(self, remote_machine):
        self.emit("remote-machine-added", remote_machine)

    @util._idle
    def emit_remote_machine_removed(self, remote_machine):
        self.emit("remote-machine-removed", remote_machine)

    @util._idle
    def remote_ops_changed(self, remote_machine):
        self.emit("remote-machine-ops-changed", remote_machine.connect_name)

    @util._async
    def start_server(self):
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=10), options=None)
        warp_pb2_grpc.add_WarpServicer_to_server(self, self.server)


        with open('/home/mtwebster/.ssh/id_rsa', 'rb') as f:
            private_key = f.read()
        with open('/home/mtwebster/.ssh/id_rsa.pub', 'rb') as f:
            certificate_chain = f.read()

        server_credentials = grpc.ssl_server_credentials(
            ((private_key, certificate_chain,),))

        self.server.add_secure_port('[::]:%d' % prefs.get_port(), server_credentials)
        self.server.start()

        self.emit_server_started()
        self.start_discovery_services()

        with self.server_runlock:
            print("Server running")
            self.server_runlock.wait()
            print("Server stopping")
            self.server.stop(grace=2).wait()
            self.emit_shutdown_complete()
            self.server = None

    @util._idle
    def emit_server_started(self):
        self.emit("server-started")

    @util._idle
    def start_discovery_services(self):
        self.start_zeroconf()
        self.start_remote_lookout()

    @util._async
    def shutdown(self):
        remote_machines = list(self.remote_machines.values())
        for machine in remote_machines:
            self.remove_service(self.zeroconf, None, machine.connect_name)

        remote_machines = None

        try:
            self.browser.cancel()
            self.zeroconf.unregister_service(self.info)
            self.zeroconf.close()
        except AttributeError as e:
            print(e)
            pass # zeroconf never started if the server never started

        with self.server_runlock:
            self.server_runlock.notify()

    @util._idle
    def emit_shutdown_complete(self):
        self.emit("shutdown-complete")

    def Ping(self, request, context):
        return void

    def GetRemoteMachineInfo(self, request, context):
        return warp_pb2.RemoteMachineInfo(display_name=GLib.get_real_name(),
                                          user_name=GLib.get_user_name())

    def GetRemoteMachineAvatar(self, request, context):
        path = os.path.join(GLib.get_home_dir(), ".face")
        if os.path.exists(path):
            return transfers.load_file_in_chunks(path)
        else:
            context.abort(code=grpc.StatusCode.NOT_FOUND, details='.face file not found!')

    def ProcessTransferOpRequest(self, request, context):
        remote_machine = self.remote_machines[request.info.connect_name]
        for existing_op in remote_machine.transfer_ops:
            if existing_op.start_time == request.info.timestamp:
                existing_op.set_status(OpStatus.WAITING_PERMISSION)
                self.add_receive_op_to_remote_machine(existing_op)
                return void

        op = ReceiveOp(request.info.connect_name)

        op.start_time = request.info.timestamp

        op.sender_name = request.sender_name
        op.receiver = request.receiver
        op.receiver_name = request.receiver_name
        op.status = OpStatus.WAITING_PERMISSION
        op.total_size = request.size
        op.total_count = request.count
        op.mime_if_single = request.mime_if_single
        op.name_if_single = request.name_if_single
        op.top_dir_basenames = request.top_dir_basenames

        op.connect("initial-setup-complete", self.add_receive_op_to_remote_machine)
        op.prepare_receive_info()

        return void

    def CancelTransferOpRequest(self, request, context):### good
        op = self.remote_machines[request.connect_name].lookup_op(request.timestamp)
        print("received cancel request at server")

        # If we receive this call, this means the op was cancelled remotely.  So,
        # our op with TO_REMOTE_MACHINE (we initiated it) was cancelled by the recipient.
        if op.direction == TransferDirection.TO_REMOTE_MACHINE:
            op.set_status(OpStatus.CANCELLED_PERMISSION_BY_RECEIVER)
        else:
            op.set_status(OpStatus.CANCELLED_PERMISSION_BY_SENDER)

        return void

    # def PauseTransferOp(self, request, context):
    #     op = self.remote_machines[request.connect_name].lookup_op(request.timestamp)

    #     # pause how?
    #     return void

    # receiver server responders
    def StartTransfer(self, request, context):
        start_time = GLib.get_monotonic_time()

        op = self.remote_machines[request.connect_name].lookup_op(request.timestamp)
        cancellable = threading.Event()
        op.file_send_cancellable = cancellable

        op.set_status(OpStatus.TRANSFERRING)

        op.progress_tracker = transfers.OpProgressTracker(op)
        op.current_progress_report = None
        sender = transfers.FileSender(op, self.service_name, request.timestamp, cancellable)

        def transfer_done():
            if sender.error != None:
                op.set_error(sender.error)
                op.stop_transfer()
                op.set_status(OpStatus.FAILED_UNRECOVERABLE)
            elif op.file_send_cancellable.is_set():
                print("File send cancelled")
            else:
                print("Transfer of %s files (%s) finished in %s" % \
                    (op.total_count, GLib.format_size(op.total_size),\
                     util.precise_format_time_span(GLib.get_monotonic_time() - start_time)))

        context.add_callback(transfer_done)
        return sender.read_chunks()

    def StopTransfer(self, request, context):
        op = self.remote_machines[request.info.connect_name].lookup_op(request.info.timestamp)

        # If we receive this call, this means the op was stopped remotely.  So,
        # our op with TO_REMOTE_MACHINE (we initiated it) was cancelled by the recipient.

        if request.error:
            op.error_msg = _("An error occurred on the remote machine")

        if op.direction == TransferDirection.TO_REMOTE_MACHINE:
            op.file_send_cancellable.set()
            print("Sender received stop transfer by receiver")
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
            print("Receiver received stop transfer by sender")
            if op.error_msg == "":
                op.set_status(OpStatus.STOPPED_BY_SENDER)
            else:
                op.set_status(OpStatus.FAILED)

        return void

    def add_receive_op_to_remote_machine(self, op):
        self.remote_machines[op.sender].add_op(op)

    def list_remote_machines(self):
        return self.remote_machines.values()
