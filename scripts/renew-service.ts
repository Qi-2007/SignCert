import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { cert, cn, rsaKeys, makeCert, privateKey, p, certPEM, pem, serial, commonName } from '../src/pki';

const name = process.argv[2], output = process.argv[3], publicURL = process.argv[4];
if (!['tsa', 'ocsp'].includes(name) || !output || !publicURL || new URL(publicURL).origin !== publicURL || !publicURL.startsWith('https://')) throw new Error('Usage: pnpm renew-service tsa|ocsp ./renewal-dir https://pki.example.com');
const issuer = cert(await readFile('pki/CA_CERT', 'utf8'));
if (Date.now() >= issuer.notAfter.value.getTime()) throw new Error('Issuer expired; use offline root to replace issuer');
const signingKey = await privateKey(await readFile('pki/CA_KEY', 'utf8'));
const keys = await rsaKeys(); const publicKey = new p.PublicKeyInfo(); await publicKey.importKey(keys.publicKey);
const c = await makeCert({ subject: cn(name === 'tsa' ? 'Signcert Timestamp Authority' : 'Signcert OCSP Responder'), publicKey, issuer, signingKey, profile: name as 'tsa' | 'ocsp', days: 365, publicURL });
if (!await c.verify(issuer)) throw new Error('Issuer key does not match issuer certificate');
const dir = resolve(output); await mkdir(dir);
const upper = name.toUpperCase(); const values = { [upper + '_CERT']: certPEM(c), [upper + '_KEY']: pem(await crypto.subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY') };
for (const [key, value] of Object.entries(values)) await writeFile(resolve(dir, key), value, { flag: 'wx', mode: 0o600 });
await writeFile(resolve(dir, 'secrets.json'), JSON.stringify(values, null, 2), { flag: 'wx', mode: 0o600 });
const quote = (s: string) => "'" + s.replace(/'/g, "''") + "'";
await writeFile(resolve(dir, 'seed.sql'), `INSERT INTO certificates (serial,pem,subject,profile,not_before,not_after,created_at) VALUES (${[serial(c.serialNumber), certPEM(c), commonName(c.subject), name, c.notBefore.value.toISOString(), c.notAfter.value.toISOString(), new Date().toISOString()].map(quote).join(',')});\n`, { flag: 'wx' });
console.log('Created renewal bundle. Import seed.sql, then upload the two new secrets. Keep old certificate records for historical OCSP queries.');
