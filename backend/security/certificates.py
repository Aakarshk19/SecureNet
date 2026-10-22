from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

def load_cert(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)

def validate_chain(leaf_pem: bytes, ca_pem: bytes):
    """Validate local one-level CA chain, issuer/signature, validity, and RSA strength."""
    leaf, ca = load_cert(leaf_pem), load_cert(ca_pem)
    now = datetime.now(timezone.utc)
    # cryptography exposes UTC-aware properties in current versions.
    if leaf.not_valid_before_utc > now or leaf.not_valid_after_utc < now:
        return False, "Certificate is not currently valid (expired or not yet valid)", leaf
    if ca.not_valid_before_utc > now or ca.not_valid_after_utc < now:
        return False, "Local CA certificate is not currently valid", leaf
    if leaf.issuer != ca.subject:
        return False, "Certificate is not issued by the trusted local CA", leaf
    try:
        ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, padding.PKCS1v15(), leaf.signature_hash_algorithm)
    except Exception:
        return False, "Certificate signature/chain validation failed", leaf
    if not isinstance(leaf.public_key(), rsa.RSAPublicKey) or leaf.public_key().key_size < 2048:
        return False, "Certificate key must be RSA-2048 or stronger", leaf
    return True, "Trusted local CA; chain and validity checks passed", leaf

def certificate_info(pem: bytes) -> dict:
    cert = load_cert(pem)
    common = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return {"subject": common[0].value if common else "(no common name)", "issuer": cert.issuer.rfc4514_string(),
            "serial_number": format(cert.serial_number, "x"), "valid_from": cert.not_valid_before_utc.isoformat(),
            "valid_until": cert.not_valid_after_utc.isoformat(), "key_size": cert.public_key().key_size}
