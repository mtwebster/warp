import time
import gettext
import threading

from gi.repository import GObject, GLib

import grpc
import warp_pb2
import warp_pb2_grpc

import prefs
import util
import transfers
import auth
from ops import SendOp, ReceiveOp
from util import TransferDirection, OpStatus, OpCommand, RemoteStatus

_ = gettext.gettext

#typedef
void = warp_pb2.VoidType()

MAX_CONNECT_RETRIES = 2

DUPLEX_WAIT_PING_TIME = 0.5
PING_TIME = 120

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

    def __init__(self, ident, hostname, display_hostname, ip, port, local_ident):
        GObject.Object.__init__(self)
        self.ip_address = ip
        self.port = port
        self.ident = ident
        self.local_ident = local_ident
        self.hostname = hostname
        self.display_hostname = display_hostname
        self.user_name = ""
        self.display_name = ""
        self.favorite = prefs.get_is_favorite(self.ident)
        self.recent_time = 0 # Keep monotonic time when visited on the user page
        self.status = RemoteStatus.INIT_CONNECTING
        self.avatar_surface = None
        self.transfer_ops = []

        self.stub = None

        self.changed_source_id = 0

        self.need_shutdown = False
        self.connected = False

        self.sort_key = self.hostname

        self.ping_timer = threading.Event()
        self.ping_time = DUPLEX_WAIT_PING_TIME
        self.channel_runlock = threading.Condition()

        prefs.prefs_settings.connect("changed::favorites", self.update_favorite_status)

    @util._async
    def start(self):
        self.ping_timer.clear()
        self.need_shutdown = False

        self.emit_machine_info_changed() # Let's make sure the button doesn't have junk in it if we fail to connect.

        print("++ Connecting to %s (%s)" % (self.display_hostname, self.ip_address))
        self.set_remote_status(RemoteStatus.INIT_CONNECTING)

        def run_secure_loop(cert):
            creds = grpc.ssl_channel_credentials(cert)

            options = (
                ('grpc.keepalive_time_ms', 10000),
                ('grpc.keepalive_timeout_ms', 5000),
                ('grpc.keepalive_permit_without_calls', True),
                ('grpc.http2.max_pings_without_data', 0),
                ('grpc.http2.min_time_between_pings_ms', 10000),
                ('grpc.http2.min_ping_interval_without_data_ms', 5000)
            )

            with grpc.secure_channel("%s:%d" % (self.ip_address, self.port), creds, options=options) as channel:
                future = grpc.channel_ready_future(channel)

                connect_retries = 0

                while not self.ping_timer.is_set():
                    try:
                        future.result(timeout=2)
                        self.stub = warp_pb2_grpc.WarpStub(channel)
                        self.connected = True
                        channel.subscribe(self.channel_connectivity_update)
                        break
                    except grpc.FutureTimeoutError:
                        if connect_retries < MAX_CONNECT_RETRIES:
                            # print("channel ready timeout, waiting 10s")
                            self.ping_timer.wait(self.ping_time)
                            connect_retries += 1
                            continue
                        else:
                            self.set_remote_status(RemoteStatus.UNREACHABLE)
                            # print("Trying to remake channel")
                            future.cancel()
                            return True

                self.set_remote_status(RemoteStatus.AWAITING_DUPLEX)

                while not self.ping_timer.is_set():
                    if self.check_duplex_connection():
                        self.set_remote_status(RemoteStatus.ONLINE)
                        self.update_remote_machine_info()
                        self.update_remote_machine_avatar()

                        break
                    else:
                        self.ping_timer.wait(self.ping_time)

                with self.channel_runlock:
                    print("Channel connected: %s" % self.hostname)
                    self.channel_runlock.wait()
                    print("Channel disconnecting: %s" % self.hostname)
                    channel.unsubscribe(self.channel_connectivity_update)

                    return False

        cert = auth.get_singleton().load_cert(self.hostname, self.ip_address)

        while run_secure_loop(cert):
            continue

        self.connected = False

    def channel_connectivity_update(self, status):
        print(status)
        if status == grpc.ChannelConnectivity.READY:
            print("READY")
            self.set_remote_status(RemoteStatus.ONLINE)
            self.update_remote_machine_info()
            self.update_remote_machine_avatar()
        elif status == grpc.ChannelConnectivity.IDLE:
            print("IDLE")
            self.set_remote_status(RemoteStatus.UNREACHABLE)

    @util._async
    def update_remote_machine_info(self):
        def get_info_finished(future):
            info = future.result()
            self.display_name = info.display_name
            self.user_name = info.user_name
            self.favorite = prefs.get_is_favorite(self.ident)

            valid = GLib.utf8_make_valid(self.display_name, -1)
            self.sort_key = GLib.utf8_collate_key(valid.lower(), -1)

            self.emit_machine_info_changed()
            self.set_remote_status(RemoteStatus.ONLINE)
        
        future = self.stub.GetRemoteMachineInfo.future(void)
        future.add_done_callback(get_info_finished)

    def check_duplex_connection(self):
        ret = self.stub.CheckDuplexConnection(warp_pb2.LookupName(id=self.local_ident))

        return ret.response

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

        transfer_op = warp_pb2.TransferOpRequest(info=warp_pb2.OpInfo(ident=op.sender,
                                                                      timestamp=op.start_time),
                                                 sender_name=op.sender_name,
                                                 receiver=self.ident,
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
            name = self.local_ident
        self.stub.CancelTransferOpRequest(warp_pb2.OpInfo(timestamp=op.start_time,
                                                          ident=name))
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
                                                                   ident=self.local_ident))

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
            name = self.local_ident

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
                                     ident=name)
            self.stub.StopTransfer(warp_pb2.StopInfo(info=opinfo, error=op.error_msg != ""))

    @util._async
    def send_files(self, uri_list):
        op = SendOp(self.local_ident,
                    self.ident,
                    self.display_name,
                    uri_list)
        self.add_op(op)
        op.prepare_send_info()

    def update_favorite_status(self, pspec, data=None):
        old_favorite = self.favorite
        self.favorite = prefs.get_is_favorite(self.ident)

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

        print("** %s is now %s" % (self.hostname, self.status))
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
        print("-- Closing connection to remote machine %s (%s)" % (self.display_hostname, self.ip_address))
        self.set_remote_status(RemoteStatus.OFFLINE)
        with self.channel_runlock:
            self.channel_runlock.notify()
        self.ping_timer.set()
        while self.connected:
            time.sleep(0.1)
