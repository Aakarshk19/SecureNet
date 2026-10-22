import { defineConfig } from 'vite'; import react from '@vitejs/plugin-react'; import { readFileSync } from 'node:fs'; import { resolve } from 'node:path';
const tls = process.env.SECURENET_HTTPS === 'true';
export default defineConfig({plugins:[react()],server:{port:5173,https:tls?{key:readFileSync(resolve('../backend/keys/server-key.pem')),cert:readFileSync(resolve('../backend/certs/server-cert.pem'))}:undefined}});
