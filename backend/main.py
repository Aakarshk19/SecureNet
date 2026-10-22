import base64, logging, time, uuid
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from backend.config import settings
from backend.database import connect, event, init_db, transfer
from backend.security.certificates import certificate_info, validate_chain
from backend.security.crypto import sha256, sign, verify
from backend.security.identity import ensure_identity
from backend.security.monitor import monitor

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("securenet")
app = FastAPI(title="SecureNet API", version="1.0.0", description="Local message and file integrity verification demo")
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in settings.allowed_origins.split(",")], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def startup(): init_db(); ensure_identity(); ensure_identity(expired=True)

def client_ip(request): return request.client.host if request.client else "unknown"
def fail(request, kind, detail, status=400):
    client = client_ip(request); event("high", kind, detail, client)
    limited, count = monitor.record_failure(client, settings.rate_limit_attempts, settings.rate_limit_window_seconds)
    if limited:
        event("critical", "rate_limited", f"{count} failed requests in {settings.rate_limit_window_seconds}s", client)
        raise HTTPException(429, "Too many invalid requests; temporarily rate limited")
    raise HTTPException(status, detail)

def check_replay(request, request_id: str, timestamp: str):
    client=client_ip(request)
    limited,count=monitor.is_limited(client,settings.rate_limit_attempts,settings.rate_limit_window_seconds)
    if limited:
        event("critical","rate_limited",f"{count} failed requests in {settings.rate_limit_window_seconds}s",client)
        raise HTTPException(429,"Too many invalid requests; temporarily rate limited")
    if not request_id or len(request_id)>128: fail(request,"invalid_request_id","Request ID must contain 1 to 128 characters")
    try: when = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError: fail(request,"invalid_timestamp","Timestamp must be ISO-8601 UTC")
    if when.tzinfo is None or abs((datetime.now(timezone.utc)-when.astimezone(timezone.utc)).total_seconds()) > 300:
        fail(request,"stale_request","Timestamp outside the five minute acceptance window")
    try:
        with connect() as db:
            db.execute("INSERT INTO nonces(request_id,created_at) VALUES(?,?)",(request_id,datetime.now(timezone.utc).isoformat()))
    except sqlite3.IntegrityError:
        # Log after the failed transaction has released its SQLite write lock.
        fail(request,"replay_attempt",f"Request ID {request_id} was already used")

async def read_upload(upload: UploadFile):
    if not upload.filename or len(upload.filename)>255: raise HTTPException(400,"A filename of at most 255 characters is required")
    data = await upload.read(settings.max_upload_mb*1024*1024+1)
    if len(data)>settings.max_upload_mb*1024*1024: raise HTTPException(413,f"File exceeds {settings.max_upload_mb} MB limit")
    return data

class SignMessage(BaseModel): message: str = Field(min_length=1,max_length=10000)

@app.get("/api/health")
def health(): return {"status":"ok","app":"SecureNet","algorithms":{"signature":"RSA-PSS","hash":"SHA-256","key_size":2048}}

@app.get("/api/overview")
def overview():
    with connect() as db:
        transfers = db.execute("SELECT COUNT(*) n FROM transfers").fetchone()["n"]
        accepted = db.execute("SELECT COUNT(*) n FROM transfers WHERE status='accepted'").fetchone()["n"]
        rejected = db.execute("SELECT COUNT(*) n FROM transfers WHERE status='rejected'").fetchone()["n"]
        events = db.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
        types = [dict(x) for x in db.execute("SELECT event_type name, COUNT(*) value FROM events GROUP BY event_type ORDER BY value DESC LIMIT 8")]
    return {"transfers":transfers,"accepted":accepted,"rejected":rejected,"security_events":events,"detection_breakdown":types}

@app.get("/api/activity")
def activity():
    today=datetime.now(timezone.utc).date()
    by_day={}
    with connect() as db:
        for row in db.execute("SELECT substr(created_at,1,10) day, status, COUNT(*) total FROM transfers WHERE created_at >= ? GROUP BY day,status",((today-timedelta(days=6)).isoformat(),)):
            by_day.setdefault(row["day"],{})[row["status"]]=row["total"]
    return [{"day":(today-timedelta(days=i)).isoformat(),"label":(today-timedelta(days=i)).strftime("%a"),"accepted":by_day.get((today-timedelta(days=i)).isoformat(),{}).get("accepted",0),"rejected":by_day.get((today-timedelta(days=i)).isoformat(),{}).get("rejected",0)} for i in reversed(range(7))]

@app.get("/api/events")
def get_events(limit:int=50):
    with connect() as db: return [dict(x) for x in db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?",(min(max(limit,1),1000),))]

@app.get("/api/transfers")
def get_transfers(limit:int=50):
    with connect() as db: return [dict(x) for x in db.execute("SELECT * FROM transfers ORDER BY id DESC LIMIT ?",(min(max(limit,1),1000),))]

@app.get("/api/certificates")
def get_certificates():
    ca, leaf, _ = ensure_identity(); trusted,reason,_=validate_chain(leaf,ca)
    return {"trusted_ca":certificate_info(ca),"demo_signer":certificate_info(leaf),"trust":reason,"is_trusted":trusted}

@app.post("/api/sign/message")
def sign_message(payload:SignMessage):
    ca, cert, key = ensure_identity(); message=payload.message.encode("utf-8"); rid=str(uuid.uuid4()); stamp=datetime.now(timezone.utc).isoformat()
    return {"message":payload.message,"signature":sign(key,message),"sha256":sha256(message),"certificate_pem":cert.decode(),"request_id":rid,"timestamp":stamp}

@app.post("/api/verify/message")
def verify_message(request:Request, message:str=Form(...), signature:str=Form(...), certificate_pem:str=Form(...), request_id:str=Form(...), timestamp:str=Form(...)):
    check_replay(request,request_id,timestamp); ca,_,_=ensure_identity()
    try: trusted, reason, cert=validate_chain(certificate_pem.encode(),ca)
    except Exception as e: fail(request,"invalid_certificate",f"Certificate could not be parsed: {e}")
    if not trusted: fail(request,"untrusted_or_expired_certificate",reason)
    valid=verify(cert.public_key(),message.encode(),signature)
    if not valid: fail(request,"invalid_signature","Message signature is invalid")
    event("info","message_verified","Valid signed message accepted",client_ip(request))
    return {"valid":True,"sha256":sha256(message.encode()),"certificate":certificate_info(certificate_pem.encode()),"message":"Signature, certificate trust, timestamp, and request ID verified"}

@app.post("/api/demo/sign-file")
async def demo_sign_file(file:UploadFile=File(...)):
    data=await read_upload(file); _,cert,key=ensure_identity(); return {"filename":file.filename,"sha256":sha256(data),"signature":sign(key,data),"certificate_pem":cert.decode(),"request_id":str(uuid.uuid4()),"timestamp":datetime.now(timezone.utc).isoformat()}

@app.post("/api/verify/file")
async def verify_file(request:Request, file:UploadFile=File(...), signature:str=Form(...), certificate_pem:str=Form(...), request_id:str=Form(...), timestamp:str=Form(...)):
    data=await read_upload(file); digest=sha256(data)
    try:
        check_replay(request,request_id,timestamp); ca,_,_=ensure_identity()
        try: trusted,reason,cert=validate_chain(certificate_pem.encode(),ca)
        except Exception as e: fail(request,"invalid_certificate",f"Certificate could not be parsed: {e}")
        if not trusted: fail(request,"untrusted_or_expired_certificate",reason)
        if not verify(cert.public_key(),data,signature): fail(request,"invalid_signature","File signature is invalid; content may have changed")
        event("info","file_verified",f"Accepted {file.filename}; SHA-256 {digest}",client_ip(request)); transfer(file.filename,digest,"accepted",request_id)
        return {"valid":True,"filename":file.filename,"sha256":digest,"certificate":certificate_info(certificate_pem.encode()),"message":"File signature and trusted certificate verified"}
    except HTTPException as exc:
        transfer(file.filename,digest,"rejected",request_id); raise exc

@app.get("/api/demo/expired-certificate")
def expired_certificate():
    ensure_identity(expired=True); return {"certificate_pem":settings.path(settings.cert_dir).joinpath("demo-expired-cert.pem").read_text(),"note":"For local negative testing only"}

@app.exception_handler(Exception)
async def unhandled(request, exc):
    log.exception("Unhandled API error",exc_info=exc); event("error","server_error","Unexpected internal error",client_ip(request))
    return JSONResponse(status_code=500,content={"detail":"Unexpected server error; see local backend log"})
