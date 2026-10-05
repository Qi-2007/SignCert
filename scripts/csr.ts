import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { rsaKeys, p, cn, pem } from '../src/pki';

const name = process.argv[2], output = process.argv[3];
if (!name || !output) throw new Error('Usage: pnpm csr "My Application" ./client-keys');
const dir = resolve(output); await mkdir(dir); // Fresh directory only.
const keys = await rsaKeys(); const publicKey = new p.PublicKeyInfo(); await publicKey.importKey(keys.publicKey);
const csr = new p.CertificationRequest({ version: 0, subject: cn(name), subjectPublicKeyInfo: publicKey });
await csr.sign(keys.privateKey, 'SHA-256');
await writeFile(resolve(dir, 'request.pem'), pem(csr.toSchema().toBER(false), 'CERTIFICATE REQUEST'), { flag: 'wx' });
await writeFile(resolve(dir, 'private.key'), pem(await crypto.subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY'), { flag: 'wx', mode: 0o600 });
console.log('Created request.pem and private.key. Send only the CSR to the CA.');
