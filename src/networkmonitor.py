import threading
import logging

import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, GObject, NM

import util

class NetDeviceInfo():
    def __init__(self, device):
        self.device = device



network_monitor = None

def get_network_monitor():
    global network_monitor

    if network_monitor == None:
        network_monitor = NetworkMonitor()

    return network_monitor

class NetworkMonitor(GObject.Object):
    __gsignals__ = {
        "ready": (GObject.SignalFlags.RUN_LAST, None, ()),
        "state-changed": (GObject.SignalFlags.RUN_LAST, None, (bool,))
    }

    def __init__(self):
        GObject.Object.__init__(self)
        logging.debug("Starting network monitor")
        self.nm_client = None
        self.sleep_timer = None
        self.online = False
        self.iface = None
        self.ip = None

        self.signals_connected = False

        NM.Client.new_async(None, self.nm_client_acquired);

    def nm_client_acquired(self, source, res, data=None):
        try:
            self.nm_client = NM.Client.new_finish(res)
            self.emit("ready")
        except GLib.Error as e:
            logging.critical("NetworkMonitor: Could not create NM Client: %s" % e.message)

    def set_active_network(self, iface, ip):
        if self.nm_client == None:
            return False

        self.iface = iface
        self.ip = ip

        self.device = self.nm_client.get_device_by_iface(self.iface)
        self.online = self.nm_check_interface_online()

        logging.debug("Current network changed (%s), connectivity: %s" % (iface, str(self.online)))

        if not self.signals_connected:
            self.nm_client.connect("notify::connectivity", self.nm_client_connectivity_changed)
            self.signals_connected = True

        return self.online

    def nm_check_interface_online(self):
        if self.device == None:
            return False

        conn = self.device.get_active_connection()

        if conn != None:
            return conn.get_state() == NM.ActiveConnectionState.ACTIVATED
        elif self.device.get_state() == NM.DeviceState.UNMANAGED:
            return util.get_ip_for_iface(self.iface) != "0.0.0.0"

        return False

    def nm_client_connectivity_changed(self, *args, **kwargs):
        online = self.nm_check_interface_online()

        if online != self.online:
            self.online = online
            self.emit_state_changed()

    def stop(self):
        logging.debug("Stopping network monitor")
        try:
            self.nm_client.disconnect_by_func(self.nm_client_connectivity_changed)
        except:
            pass

        self.nm_client = None

    # def get_interfaces(self):
    #     return self.

    @util._idle
    def emit_state_changed(self):
        logging.debug("Network state changed: online = %s" % str(self.online))
        self.emit("state-changed", self.online)
