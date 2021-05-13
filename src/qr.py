#!/usr/bin/python3

import os
import json
import gettext
import tempfile

from qrcodegen import *

from gi.repository import Gtk, GdkPixbuf, Gdk

import util
import prefs
import auth
import config
import networkmonitor

_ = gettext.gettext

class QRWindow():
    def __init__(self, transient_for):
        self.builder = Gtk.Builder.new_from_file(os.path.join(config.pkgdatadir, "qr-window.ui"))

        self.window = self.builder.get_object("qr_window")
        self.window.set_title(title=_("Connection Info"))
        self.window.set_transient_for(transient_for)

        self.qr_image = self.builder.get_object("qr_image")
        self.qr_entry = self.builder.get_object("qr_entry")
        self.qr_clip_button = self.builder.get_object("qr_clip_button")
        self.qr_clip_button.connect("clicked", self.copy_to_clipboard)
        self.close_button = self.builder.get_object("qr_window_close_button")

    def generate_code(self):
        info = {}
        info["ident"] = auth.get_singleton().get_ident()
        info["port"] = prefs.get_port()
        info["auth-port"] = prefs.get_auth_port()
        info["hostname"] = util.get_hostname()
        info["api-version"] = config.RPC_API_VERSION
        info["ipv4"] = networkmonitor.get_network_monitor().get_ips().ip4

        j = json.dumps(info)
        self.qr_entry.set_text(j)

        tmp_name = None
        with tempfile.NamedTemporaryFile(delete=False) as f:
            tmp_name = f.name

            qr = QrCode.encode_text(j, QrCode.Ecc.MEDIUM)
            svg = qr.to_svg_str(4)
            f.write(svg.encode("utf-8"))

        scale = self.window.get_scale_factor()
        pixbuf = GdkPixbuf.Pixbuf.new_from_file_at_scale(tmp_name, -1, 192 * scale, True)
        if pixbuf == None:
            raise Exception

        # logo = GdkPixbuf.Pixbuf.new_from_file_at_scale("/usr/share/icons/hicolor/scalable/apps/org.x.Warpinator-symbolic.svg", -1, 64 * scale, True)
        # logo.copy_area(0, 0, 64 * scale, 64 * scale, pixbuf, (192 / 2 - 64 / 2) * scale, (192 / 2 - 64 / 2) * scale)

        surf = Gdk.cairo_surface_create_from_pixbuf(pixbuf, scale, None)
        self.qr_image.set_from_surface(surf)

        os.unlink(tmp_name)

    def copy_to_clipboard(self, button, data=None):
        Gtk.Clipboard.get_default(Gdk.Display.get_default()).set_text(self.qr_entry.get_text(), -1)

def show_window(window, time):
    w = QRWindow(window)
    w.generate_code()

    w.window.show_all()
    w.window.present_with_time(time)