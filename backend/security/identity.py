"""Create local-only development CA and demo identities on first run."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.x509 import DNSName, IPAddress
import ipaddress
from backend.config import settings

def _key(path: Path):
    if path.exists(): return serialization.load_pem_private_key(path.read_bytes(), None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    try: path.chmod(0o600)
    except OSError: pass
    return key

def ensure_identity(expired=False):
    certdir, keydir = settings.path(settings.cert_dir), settings.path(settings.key_dir)
    certdir.mkdir(parents=True, exist_ok=True); keydir.mkdir(parents=True, exist_ok=True)
    ca_key = _key(keydir / "local-ca-key.pem"); ca_path = certdir / "local-ca.pem"
    if not ca_path.exists():
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureNet Local Test CA")])
        now = datetime.now(timezone.utc)
        ca = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(ca_key,hashes.SHA256())
        ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    # Optional local HTTPS identity for Uvicorn. Browsers will require the CA to
    # be explicitly trusted; this is a development certificate only.
    server_key = _key(keydir / "server-key.pem")
    server_path = certdir / "server-cert.pem"
    if not server_path.exists():
        ca = x509.load_pem_x509_certificate(ca_path.read_bytes()); now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        server_cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca.subject).public_key(server_key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
            .add_extension(x509.SubjectAlternativeName([DNSName("localhost"),IPAddress(ipaddress.ip_address("127.0.0.1"))]),critical=False)
            .sign(ca_key,hashes.SHA256()))
        server_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    user_key = _key(keydir / "demo-signer-key.pem")
    leaf_path = certdir / ("demo-expired-cert.pem" if expired else "demo-signer-cert.pem")
    if not leaf_path.exists():
        ca = x509.load_pem_x509_certificate(ca_path.read_bytes()); now = datetime.now(timezone.utc)
        start = now-timedelta(days=30) if not expired else now-timedelta(days=20)
        end = now+timedelta(days=365) if not expired else now-timedelta(days=1)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureNet Demo Signer" if not expired else "Expired Demo Signer")])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(ca.subject).public_key(user_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).sign(ca_key,hashes.SHA256())
        leaf_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return ca_path.read_bytes(), leaf_path.read_bytes(), (keydir/"demo-signer-key.pem").read_bytes()
