from cryptography import x509
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.x509.oid import NameOID

import datetime
import stat
import os

from gi.repository import GLib, GObject

import util

day = datetime.timedelta(1, 0, 0)
EXPIRE_TIME = 30 * day

CERT_FOLDER = os.path.join(GLib.get_user_config_dir(), "warp", "remotes")
os.makedirs(CERT_FOLDER, 0o700, exist_ok=True)

class Authentication(GObject.Object):
    def __init__(self):
        self.hostname = util.get_hostname()

    def load_cert(self, hostname):
        path = os.path.join(CERT_FOLDER, self.hostname + ".pem")

        return self.load_bytes(path)

    def load_private_key(self):
        path = os.path.join(CERT_FOLDER, self.hostname + "-key.pem")

        return self.load_bytes(path)

    def load_bytes(self, path):
        ret = None

        try:
            with open(path, "rb") as f:
                ret = f.read()
        except FileNotFoundError:
            pass

        return ret

    def save_cert(self, hostname, cert_bytes):
        path = os.path.join(CERT_FOLDER, self.hostname + ".pem")

        self.save_bytes(path, cert_bytes)

    def save_private_key(self, key_bytes):
        path = os.path.join(CERT_FOLDER, self.hostname + "-key.pem")

        self.save_bytes(path, key_bytes)

    def save_bytes(self, path, file_bytes):
        try:
            os.remove(path)
        except OSError:
            pass

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        mode = stat.S_IRUSR | stat.S_IWUSR
        umask = 0o777 ^ mode  # Prevents always downgrading umask to 0.

        umask_original = os.umask(umask)

        try:
            fdesc = os.open(path, flags, mode)
        finally:
            os.umask(umask_original)

        with os.fdopen(fdesc, 'wb') as f:
            f.write(file_bytes)

    def make_key_cert_pair(self, hostname, ip):
        private_key = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=65537,
            key_size=2048
        )

        public_key = private_key.public_key()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]))
        builder = builder.not_valid_before(datetime.datetime.today() - day)
        builder = builder.not_valid_after(datetime.datetime.today() + EXPIRE_TIME)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(ip)]
            ),
            critical=True
        )

        certificate = builder.sign(
            private_key=private_key, algorithm=hashes.SHA256(),
            backend=crypto_default_backend()
        )

        ser_private_key = private_key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption())

        ser_public_key = certificate.public_bytes(
            crypto_serialization.Encoding.PEM
        )

        return ser_private_key, ser_public_key

    def create_new_for_local(self):
        key, cert = self.make_key_cert_pair(self.hostname, util.get_ip())

        self.save_private_key(key)
        self.save_cert(self.hostname, cert)

if __name__ == "__main__":
    a = Authentication()

    print("generating")
    key, cert = a.make_key_cert_pair("mike-p51", "10.0.0.36")

    print("saving")
    a.save_remote_cert("mike-p51", cert)
    a.save_remote_cert("mike-p51-priv", key)


    print("loading")
    a.load_remote_cert("mike-p51")