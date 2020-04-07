
from cryptography import x509
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.x509.oid import NameOID
import nacl
from nacl import secret
import hashlib
import datetime
import stat
import os

from gi.repository import GLib, GObject

import util

day = datetime.timedelta(1, 0, 0)
EXPIRE_TIME = 30 * day

DEFAULT_GROUP_CODE = b"Warpinator"
CONFIG_FOLDER = os.path.join(GLib.get_user_config_dir(), "warp")
CERT_FOLDER = os.path.join(CONFIG_FOLDER, "remotes")

os.makedirs(CERT_FOLDER, 0o700, exist_ok=True)

class AuthManager(GObject.Object):
    def __init__(self):
        self.hostname = util.get_hostname()
        self.get_server_creds()

    def load_cert(self, hostname):
        path = os.path.join(CERT_FOLDER, hostname + ".pem")
        return self.load_bytes(path)

    def load_private_key(self):
        path = os.path.join(CERT_FOLDER, self.hostname + "-key.pem")

        return self.load_bytes(path)

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

    def load_bytes(self, path):
        ret = None

        try:
            with open(path, "rb") as f:
                ret = f.read()
        except FileNotFoundError:
            pass

        return ret

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

    def lookup_single_by_oid(self, name_attrs, oid):
        res = name_attrs.get_attributes_for_oid(oid)

        if res and res[0]:
            return res[0].value

        return None

    def ip_and_hostname_matches_certificate(self, ip, hostname, data):
        cert_ip = None
        backend = crypto_default_backend()
        instance = x509.load_pem_x509_certificate(data, backend)

        issuer = self.lookup_single_by_oid(instance.issuer, x509.NameOID.COMMON_NAME)
        subject = self.lookup_single_by_oid(instance.subject, x509.NameOID.COMMON_NAME)

        if issuer != subject:
            return False

        for ext in instance.extensions:
            if isinstance(ext.value, x509.SubjectAlternativeName):
                for item in ext.value:
                    if isinstance(item, x509.DNSName):
                        cert_ip = item.value

        return issuer == hostname and cert_ip == ip

    def get_server_creds(self):
        key = self.load_private_key()
        cert = self.load_cert(util.get_hostname())

        if (key != None and cert != None) and self.ip_and_hostname_matches_certificate(self.hostname,
                                                                                       util.get_ip(),
                                                                                       cert):
            print("Using existing server credentials")
            return (key, cert)

        print("Creating server credentials")
        key, cert = self.make_key_cert_pair(self.hostname, util.get_ip())

        try:
            self.save_private_key(key)
            self.save_cert(self.hostname, cert)
        except OSError as e:
            print("Unable to save new server key and/or certificate: %s" % e)

        return (key, cert)

    def get_boxed_server_cert(self):
        hasher = hashlib.sha256()
        hasher.update(self.get_group_code())
        key = hasher.digest()

        encoder = secret.SecretBox(key)

        encrypted = encoder.encrypt(self.load_cert(self.hostname))
        # print("encrypted: ", encrypted)
        return encrypted

    def unbox_server_cert(self, box):
        hasher = hashlib.sha256()
        hasher.update(self.get_group_code())
        key = hasher.digest()
        # print("decrypt: ", box)
        decoder = secret.SecretBox(key)

        try:
            cert = decoder.decrypt(box)
        except nacl.exceptions.CryptoError as e:
            # do something
            print(e)
            return None

        return cert

    def get_group_code(self):
        path = os.path.join(CONFIG_FOLDER, ".groupcode")

        code = self.load_bytes(path)

        if code == None:
            code = DEFAULT_GROUP_CODE
            self.save_group_code(code)

        return code

    def save_group_code(self, code):
        path = os.path.join(CONFIG_FOLDER, ".groupcode")

        self.save_bytes(path, code)

    def validate_remote_creds(self, hostname, ip, box):
        cert = self.unbox_server_cert(box)

        if cert and self.ip_and_hostname_matches_certificate(cert):
            print("matches")
            self.save_cert(hostname, cert)
            return True

        return False

    def process_remote_cert(self, hostname, zc_dict):
        print(zc_dict)
        box = b''
        for key in zc_dict.keys():
            box += key
        print(box)
        cert = self.unbox_server_cert(box)
        if cert:
            self.save_cert(hostname, cert)

if __name__ == "__main__":
    a = AuthManager()

    a.get_server_creds()