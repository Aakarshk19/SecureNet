from fastapi.testclient import TestClient
import pytest
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from backend.main import app
from backend.security.monitor import monitor

@pytest.fixture()
def client():
    monitor.failures.clear()
    with TestClient(app) as c: yield c

def signed_file(client, content=b"network packet sample.txt"):
    s=client.post('/api/demo/sign-file',files={'file':('sample.txt',content,'text/plain')})
    assert s.status_code==200
    return s.json(),content

def verify_file(client,signed,content=None,**overrides):
    form={k:overrides.get(k,signed[k]) for k in ('signature','certificate_pem','request_id','timestamp')}
    return client.post('/api/verify/file',data=form,files={'file':('sample.txt',content if content is not None else b'network packet sample.txt','text/plain')})

def test_valid_signed_file_is_accepted(client):
    s,data=signed_file(client)
    r=verify_file(client,s,data)
    assert r.status_code==200 and r.json()['valid'] is True

def test_modified_file_is_rejected_and_logged(client):
    s,_=signed_file(client)
    r=verify_file(client,s,b"tampered network packet")
    assert r.status_code==400 and 'signature' in r.json()['detail'].lower()
    assert any(x['event_type']=='invalid_signature' for x in client.get('/api/events').json())

def test_expired_certificate_is_rejected(client):
    s,data=signed_file(client)
    expired=client.get('/api/demo/expired-certificate').json()['certificate_pem']
    r=verify_file(client,s,data,certificate_pem=expired)
    assert r.status_code==400 and 'valid' in r.json()['detail'].lower()

def test_untrusted_certificate_is_rejected(client):
    s,data=signed_file(client)
    foreign_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    foreign_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Untrusted test signer')])
    now=datetime.now(timezone.utc)
    foreign_cert=(x509.CertificateBuilder().subject_name(foreign_name).issuer_name(foreign_name)
        .public_key(foreign_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).sign(foreign_key,hashes.SHA256()))
    s['certificate_pem']=foreign_cert.public_bytes(serialization.Encoding.PEM).decode()
    r=verify_file(client,s,data)
    assert r.status_code==400 and 'trusted local CA' in r.json()['detail']

def test_replayed_request_id_is_rejected(client):
    s,data=signed_file(client)
    assert verify_file(client,s,data).status_code==200
    r=verify_file(client,s,data)
    assert r.status_code==400 and 'already used' in r.json()['detail']

def test_repeated_invalid_requests_are_rate_limited(client):
    s,data=signed_file(client); s['signature']='bm90LWEtdmFsaWQtc2lnbmF0dXJl'
    codes=[]
    for _ in range(5):
        # unique request IDs ensure these are invalid signatures, not replay retries
        import uuid
        r=verify_file(client,s,data,request_id=str(uuid.uuid4())); codes.append(r.status_code)
    assert codes[:4]==[400]*4 and codes[4]==429
    assert any(x['event_type']=='rate_limited' for x in client.get('/api/events').json())
