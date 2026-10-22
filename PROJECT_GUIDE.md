# SecureNet project guide

This guide explains how to start the project and use each dashboard feature. SecureNet is a local network security demonstration: it signs files and messages, verifies that they have not changed, checks whether the signing certificate is trusted and current, and records invalid or replayed attempts.

## 1. Start SecureNet

Open the project folder in VS Code. Use two integrated PowerShell terminals.

### Terminal 1: backend API

Run these commands from the project root (the folder containing `requirements.txt`). The `--reload-dir backend` option limits auto-reload watching to application source, so installing packages in `.venv` does not trigger restart loops:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload --reload-dir backend
```

If `.venv` has not been created yet, install the backend first:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload --reload-dir backend
```

Wait for Uvicorn to report that it is running. On first start, SecureNet generates local test keys and certificates and creates its SQLite database. Leave this terminal running.

### Terminal 2: React dashboard

```powershell
cd frontend
npm.cmd install
npm.cmd run dev
```

Open the Vite URL printed in this terminal, normally `http://localhost:5173`. The API docs are available at `http://127.0.0.1:8000/docs` and the health check is `http://127.0.0.1:8000/api/health`.

**If the dashboard says “API offline” or shows certificate details as “Loading…”:** the dashboard request did not complete. Check that Terminal 1 is running and visit the health URL above. If health returns `status: ok` but the dashboard still reports offline, the browser is probably blocking the request because of CORS or an HTTP/HTTPS mismatch. The dashboard address and API address must use compatible schemes, and the exact dashboard origin (scheme, host, and port) must be listed in root `.env` as `ALLOWED_ORIGINS`. The supplied `.env.example` allows the common `localhost` and `127.0.0.1` Vite origins on port 5173. After editing `.env`, restart the backend, then click dashboard refresh.

If a backend terminal appears to be running but `/api/health` hangs, stop that server with **Ctrl+C** in its terminal and restart it. I checked this workspace: the process on port 8000 was accepting connections but not returning responses, while a fresh instance on port 8001 returned a healthy response. If port 8000 keeps hanging or is occupied, use this temporary alternate-port setup:

Terminal 1, from the project root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload --reload-dir backend --host 127.0.0.1 --port 8001
```

Terminal 2:

```powershell
cd frontend
$env:VITE_API_URL = "http://127.0.0.1:8001/api"
npm.cmd run dev
```

Open the new Vite URL and confirm `http://127.0.0.1:8001/api/health` returns JSON with `"status":"ok"`. Vite reads `VITE_API_URL` when it starts, so restart it after changing that variable.

## 2. Understand the dashboard

- **Overview:** summary counts, seven day file verification activity, certificate trust summary, recent file transfers, signing tools, and recent security events. Counts start at zero in a fresh database.
- **File verification:** the sidebar scrolls to the file integrity controls. The page also lists recent file verification records in the transfer table.
- **Signing tools:** scrolls to the message signing form. Sign the current text first, then verify that signature.
- **Certificates:** scrolls to the certificate trust card. It displays the generated demo signer subject, issuing local CA, RSA key size, and expiry date.
- **Security events:** scrolls to the event log. Invalid signatures, certificate failures, replay attempts, and rate limiting appear here.
- **Refresh icon:** fetches dashboard data from the API immediately.
- **Search files:** filters the recent transfer table by filename.
- **Secure HTTPS / Local HTTP pill:** reports whether the page is open over HTTPS or the normal local development HTTP address. The standard setup uses local HTTP; see the TLS steps in `README.md` to try local HTTPS.
- **View all / View all transfers:** expands the saved security event list or file transfer table. These records come from the SQLite database and are ordered newest first. Click **Show recent** to collapse the section again. The event and transfer API endpoints return up to 1,000 records for this local dashboard.

The overview is a single scrollable dashboard. The sidebar items jump to the related feature; scroll down to see the full transfer table, file and message tools, and event log.

## 3. Verify a valid file

1. Open **File verification** in the sidebar (or click **Verify a file** in the welcome panel).
2. Click **Sign file** and choose a small test file. The local demo signer creates a SHA-256 digest and RSA-PSS signature; the private key stays on the backend.
3. When the success message says the file was signed, click **Choose & verify** and choose the same unchanged file again.
4. SecureNet should report that the file is accepted. The accepted transfer and a successful verification event will appear in the dashboard after refresh.

Signing and verifying are separate actions so you can edit the file between them to demonstrate tampering.

## 4. Detect a modified file

1. Sign a test file using **Sign file**.
2. Change its contents and save it, or choose a different file, then click **Choose & verify**.
3. SecureNet should reject the signature because it no longer matches the uploaded bytes. The rejected transfer and `invalid_signature` event are recorded.

If you verify the original signed envelope a second time without signing again, SecureNet will also reject it as a replay because its request ID has already been used. That replay event is expected. Sign the file again to obtain a fresh request ID before doing another verification.

The signature is bound to the exact file bytes. Renaming the file without changing its contents does not invalidate the signature; editing the bytes does.

## 5. Sign and verify a message

1. Open **Signing tools** in the sidebar.
2. Edit the text box and click **Sign message**. SecureNet returns a signature and public certificate for the text shown at signing time.
3. Click **Verify signature**. A valid signature and trusted certificate are accepted and a security event is recorded.
4. To check a different message, edit the text and click **Sign message** again before verifying it.

Request IDs are single use. Clicking **Verify signature** a second time on the same signed message is expected to be rejected as a replay. Sign again to get a fresh request ID.

## 6. Explore certificates

Open **Certificates** to see the current local demo signer’s public certificate information. The generated test Certificate Authority is the local trust anchor. The backend checks the signer certificate’s validity dates, issuer, CA signature, and RSA key strength before accepting a signature.

The private keys are local demo artifacts under `backend/keys/` and are excluded from Git. Do not share or use these generated keys for real data. The expired certificate is intentionally provided only for negative testing; it is not the active dashboard signer.

## 7. Review activity and events

- The statistic cards count accepted files, rejected files, all security events, and file transfers.
- The chart shows accepted and rejected **file** verifications grouped by day for the last seven days. It is based on SQLite transfer records, so it is empty before file checks occur.
- The **Recent transfers** table shows filename, SHA-256 digest, accepted/rejected status, request ID, and time. Search filters filenames; Refresh reloads the table.
- The **Security event log** shows the latest monitored actions. It can include successful checks as well as invalid signatures, untrusted/expired certificates, stale requests, replay attempts, and rate limiting.

## 8. Run all six security demonstrations

From the project root, run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The automated tests create local test identities as needed and verify all required cases: a valid file is accepted; modified bytes are rejected; an untrusted signer is rejected; an expired certificate is rejected; reuse of a request ID is rejected; and repeated invalid requests are logged and rate limited. This is the easiest way to reproduce the certificate and rate limit demonstrations. The dashboard directly supports valid file, modified file, and message signing flows.

Default limits are 10 MB per upload and five failed verification requests per client in a rolling 60 second window. These values can be changed in the root `.env` file; restart the backend after editing it.

## 9. Troubleshooting

| What you see | What to check |
|---|---|
| `API offline` / connection error | Start the backend from the project root and check `http://127.0.0.1:8000/api/health`. |
| Health returns 200 but dashboard remains offline | Check the browser address and make sure that exact origin is allowed in root `.env` `ALLOWED_ORIGINS` (for example `http://127.0.0.1:5173`); restart the backend after changing `.env`. Keep both frontend and API on HTTP for normal development, or configure both for HTTPS. |
| Port 8000 accepts a connection but health never responds | Stop the old Uvicorn process with Ctrl+C in its terminal and restart it; if needed, use the alternate port 8001 instructions in section 1. |
| WatchFiles repeatedly reloads files under `.venv\Lib\site-packages` | Stop Uvicorn with Ctrl+C. Finish `pip install` first, then restart with `--reload-dir backend` as shown in section 1. The virtual environment is not application source and should not be watched. |
| `Loading…` in the certificate card | The initial API request did not complete. Start/restart the backend, then refresh the page. |
| Browser cannot find `npm` | In PowerShell use `npm.cmd`, not `npm`. |
| PowerShell blocks virtual environment activation | Do not activate it; invoke ` .\.venv\Scripts\python.exe ` directly as shown above. |
| Upload is rejected for size | Use a smaller file or increase `MAX_UPLOAD_MB` in `.env`, then restart the backend. |
| HTTP 429 after bad verification attempts | Wait for the default 60 second failure window to pass, or restart the local demo API. |
| HTTPS certificate warning | The local test CA is not publicly trusted. See the development TLS section in `README.md`; do not use the demo CA for production. |

## 10. What this demo does not provide

The normal local setup uses HTTP. TLS can be enabled for a local demonstration as described in `README.md`. The demo signer’s private key is stored locally without a hardware key store, the CA is not a public authority, and certificate validation does not implement full production PKI path building or revocation. Use the project to understand the security checks, not to protect production communications.
