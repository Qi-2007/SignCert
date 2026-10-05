import { mkdir, writeFile } from 'node:fs/promises';
import { createPrivateKey, randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { cn, rsaKeys, makeCert, p, certPEM, pem, serial, commonName, hex, type Profile } from '../src/pki';

const url = process.argv[2];
const passphrase = process.env.ROOT_PASSPHRASE;
if (!url || new URL(url).protocol !== 'https:' || new URL(url).origin !== url || !passphrase || passphrase.length < 16) {
  throw new Error('Usage: ROOT_PASSPHRASE (16+ chars) and pnpm bootstrap https://pki.example.com (origin only)');
}
const dir = resolve('pki');
await mkdir(dir); // Fail if it exists: never overwrite an existing CA.
const rootKeys = await rsaKeys();
const rootPublic = new p.PublicKeyInfo(); await rootPublic.importKey(rootKeys.publicKey);
const root = await makeCert({ subject: cn('Signcert Root CA'), publicKey: rootPublic, signingKey: rootKeys.privateKey, profile: 'root', days: 3650 });
const rootPKCS8 = await crypto.subtle.exportKey('pkcs8', rootKeys.privateKey);
const encryptedRoot = createPrivateKey({ key: Buffer.from(rootPKCS8), format: 'der', type: 'pkcs8' }).export({ format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase });
await writeFile(resolve(dir, 'root-encrypted.key'), encryptedRoot, { flag: 'wx', mode: 0o600 });
await writeFile(resolve(dir, 'root.pem'), certPEM(root), { flag: 'wx' });
const issuerKeys = await rsaKeys(); const issuerPublic = new p.PublicKeyInfo(); await issuerPublic.importKey(issuerKeys.publicKey);
const issuer = await makeCert({ subject: cn('Signcert Issuing CA'), publicKey: issuerPublic, issuer: root, signingKey: rootKeys.privateKey, profile: 'issuer', days: 1825 });
const values: Record<string, string> = { ROOT_CERT: certPEM(root), CA_CERT: certPEM(issuer), CA_KEY: pem(await crypto.subtle.exportKey('pkcs8', issuerKeys.privateKey), 'PRIVATE KEY'), ADMIN_TOKEN: hex(randomBytes(32)), TSA_CUSTOM_TOKEN: hex(randomBytes(32)) };
const services: { certificate: p.Certificate; profile: Profile }[] = [{ certificate: issuer, profile: 'issuer' }];
for (const name of ['tsa', 'ocsp'] as const) {
  const keys = await rsaKeys(); const publicKey = new p.PublicKeyInfo(); await publicKey.importKey(keys.publicKey);
  const c = await makeCert({ subject: cn(name === 'tsa' ? 'Signcert Timestamp Authority' : 'Signcert OCSP Responder'), publicKey, issuer, signingKey: issuerKeys.privateKey, profile: name, days: 365, publicURL: url });
  values[name.toUpperCase() + '_CERT'] = certPEM(c);
  values[name.toUpperCase() + '_KEY'] = pem(await crypto.subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY');
  services.push({ certificate: c, profile: name });
}
for (const [name, value] of Object.entries(values)) await writeFile(resolve(dir, name), value, { flag: 'wx', mode: 0o600 });
await writeFile(resolve(dir, 'issuer.pem'), values.CA_CERT);
await writeFile(resolve(dir, 'tsa.pem'), values.TSA_CERT);
await writeFile(resolve(dir, 'ocsp.pem'), values.OCSP_CERT);
await writeFile(resolve(dir, 'chain.pem'), values.CA_CERT + values.ROOT_CERT);
await writeFile(resolve(dir, 'secrets.json'), JSON.stringify(values, null, 2), { flag: 'wx', mode: 0o600 });
await writeFile('.dev.vars', Object.entries({ ...values, PUBLIC_URL: url }).map(([key, value]) => `${key}=${JSON.stringify(value)}`).join('\n') + '\n', { flag: 'wx', mode: 0o600 });
const quote = (s: string) => "'" + s.replace(/'/g, "''") + "'";
const sql = services.map(({ certificate: c, profile }) => `INSERT INTO certificates (serial,pem,subject,profile,not_before,not_after,created_at) VALUES (${[serial(c.serialNumber), certPEM(c), commonName(c.subject), profile, c.notBefore.value.toISOString(), c.notAfter.value.toISOString(), new Date().toISOString()].map(quote).join(',')});`).join('\n');
await writeFile(resolve(dir, 'seed.sql'), sql, { flag: 'wx' });
console.log('Created pki/ and .dev.vars. Keep encrypted root offline. Private keys were not printed. Import seed.sql before using the services.');
