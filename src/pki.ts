import * as a from 'asn1js';
import * as p from 'pkijs';

p.setEngine('webcrypto', new p.CryptoEngine({ name: 'webcrypto', crypto: globalThis.crypto, subtle: globalThis.crypto.subtle }));
export { a, p };
export const OID = {
  sha1: '1.3.14.3.2.26', sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2', sha512: '2.16.840.1.101.3.4.2.3',
  tsa: '1.3.6.1.5.5.7.3.8', ocsp: '1.3.6.1.5.5.7.3.9',
  nonce: '1.3.6.1.5.5.7.48.1.2', tst: '1.2.840.113549.1.9.16.1.4',
};
export const HASHES: Record<string, { name: string; size: number }> = {
  [OID.sha256]: { name: 'SHA-256', size: 32 },
  [OID.sha384]: { name: 'SHA-384', size: 48 },
  [OID.sha512]: { name: 'SHA-512', size: 64 },
};
export function decode(data: ArrayBuffer): a.AsnType {
  if (data.byteLength > 65536 || data.byteLength === 0) throw new Error('Invalid DER size');
  const result = a.fromBER(data);
  if (result.offset !== data.byteLength || result.result.error) throw new Error('Invalid DER');
  return result.result;
}
export function unpem(value: string, label: string): ArrayBuffer {
  const match = value.match(new RegExp(`^\\s*-----BEGIN ${label}-----([A-Za-z0-9+/=\\s]+)-----END ${label}-----\\s*$`));
  if (!match) throw new Error(`Expected PEM ${label}`);
  return Uint8Array.from(atob(match[1].replace(/\s/g, '')), c => c.charCodeAt(0)).buffer;
}
export function base64(data: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(data)));
}
export function pem(data: ArrayBuffer, label: string): string {
  return `-----BEGIN ${label}-----\n${base64(data).match(/.{1,64}/g)!.join('\n')}\n-----END ${label}-----\n`;
}
export function cert(value: string): p.Certificate { return new p.Certificate({ schema: decode(unpem(value, 'CERTIFICATE')) }); }
export function hex(data: ArrayBuffer | Uint8Array): string {
  return Array.from(data instanceof Uint8Array ? data : new Uint8Array(data), v => v.toString(16).padStart(2, '0')).join('');
}
export function serial(value: a.Integer): string {
  if (value.valueBlock.valueHexView[0] & 128) throw new Error('Negative serial');
  return hex(value.valueBlock.valueHexView).replace(/^0+/, '') || '0';
}
export function randomSerial(): a.Integer {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  bytes[0] = (bytes[0] & 0x7f) | 0x40;
  return new a.Integer({ valueHex: bytes.buffer });
}
export const digest = (data: ArrayBuffer, hash = 'SHA-256') => crypto.subtle.digest(hash, data);
export function ext(oid: string, value: a.AsnType, critical = false): p.Extension {
  return new p.Extension({ extnID: oid, critical, extnValue: value.toBER(false) });
}
export function cn(name: string): p.RelativeDistinguishedNames {
  if (!name || name.length > 128 || /[\x00-\x1f]/.test(name)) throw new Error('Invalid common name');
  return new p.RelativeDistinguishedNames({ typesAndValues: [new p.AttributeTypeAndValue({ type: '2.5.4.3', value: new a.Utf8String({ value: name }) })] });
}
export function commonName(subject: p.RelativeDistinguishedNames): string {
  const values = subject.typesAndValues.filter(v => v.type === '2.5.4.3');
  if (values.length !== 1) throw new Error('CSR needs exactly one common name');
  const value = values[0].value;
  if (!(value instanceof a.Utf8String || value instanceof a.PrintableString)) throw new Error('Unsupported CN encoding');
  cn(value.valueBlock.value);
  return value.valueBlock.value;
}
export async function rsaKeys(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
}
export async function privateKey(value: string, hash = 'SHA-256'): Promise<CryptoKey> {
  return crypto.subtle.importKey('pkcs8', unpem(value, 'PRIVATE KEY'), { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['sign']);
}
export type Profile = 'code-signing' | 'server' | 'client' | 'tsa' | 'ocsp' | 'root' | 'issuer';
export interface MakeCert {
  subject: p.RelativeDistinguishedNames; publicKey: p.PublicKeyInfo;
  issuer?: p.Certificate; signingKey: CryptoKey; profile: Profile;
  days: number; publicURL?: string; dnsNames?: string[]; now?: Date;
  notBefore?: Date; notAfter?: Date;
}
export function dnsNames(input: unknown): string[] {
  if (!Array.isArray(input) || !input.length || input.length > 20) throw new Error('Provide 1–20 DNS names');
  return [...new Set(input.map(v => {
    if (typeof v !== 'string' || v.length > 253 || !/^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(v)) throw new Error('Invalid DNS name; use lowercase ASCII/IDNA');
    return v;
  }))];
}
export async function makeCert(opts: MakeCert): Promise<p.Certificate> {
  const now = opts.now ?? new Date();
  const isCA = opts.profile === 'root' || opts.profile === 'issuer';
  const start = new Date(Math.ceil((opts.notBefore?.getTime() ?? Math.max(now.getTime() - 60000, opts.issuer?.notBefore.value.getTime() ?? -Infinity)) / 1000) * 1000);
  const end = new Date(Math.floor((opts.notAfter?.getTime() ?? Math.min(now.getTime() + opts.days * 86400000, opts.issuer?.notAfter.value.getTime() ?? Infinity)) / 1000) * 1000);
  if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || start.getTime() >= end.getTime()) throw new Error('Invalid certificate validity interval');
  if (opts.issuer && (start < opts.issuer.notBefore.value || end > opts.issuer.notAfter.value)) throw new Error('Certificate validity must be within issuer validity');
  const time = (value: Date) => new p.Time({type:value.getUTCFullYear() < 1950 || value.getUTCFullYear() >= 2050 ? 1 : 0,value});
  const c = new p.Certificate({ version: 2, serialNumber: randomSerial(), subject: opts.subject,
    issuer: opts.issuer?.subject ?? opts.subject, subjectPublicKeyInfo: opts.publicKey,
    notBefore: time(start),
    notAfter: time(end),
  });
  const ski = await digest(c.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView.slice().buffer, 'SHA-1');
  const issuerSKI = opts.issuer ? await digest(opts.issuer.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView.slice().buffer, 'SHA-1') : ski;
  c.extensions = [
    ext('2.5.29.19', new p.BasicConstraints(isCA ? { cA: true, pathLenConstraint: opts.profile === 'root' ? 1 : 0 } : { cA: false }).toSchema(), true),
    ext('2.5.29.15', new a.BitString({ valueHex: new Uint8Array([isCA ? 0x06 : 0x80]).buffer, unusedBits: isCA ? 1 : 7 }), true),
    ext('2.5.29.14', new a.OctetString({ valueHex: ski })),
    ext('2.5.29.35', new p.AuthorityKeyIdentifier({ keyIdentifier: new a.OctetString({ valueHex: issuerSKI }) }).toSchema()),
  ];
  const purposes: Partial<Record<Profile, string>> = { 'code-signing': '1.3.6.1.5.5.7.3.3', server: '1.3.6.1.5.5.7.3.1', client: '1.3.6.1.5.5.7.3.2', tsa: OID.tsa, ocsp: OID.ocsp };
  if (purposes[opts.profile]) c.extensions.push(ext('2.5.29.37', new p.ExtKeyUsage({ keyPurposes: [purposes[opts.profile]!] }).toSchema(), opts.profile === 'tsa'));
  if (opts.profile === 'server') c.extensions.push(ext('2.5.29.17', new p.GeneralNames({ names: dnsNames(opts.dnsNames).map(value => new p.GeneralName({ type: 2, value })) }).toSchema()));
  if (opts.profile === 'ocsp') c.extensions.push(ext('1.3.6.1.5.5.7.48.1.5', new a.Null()));
  if (opts.publicURL && opts.issuer && opts.profile !== 'issuer') {
    c.extensions.push(ext('1.3.6.1.5.5.7.1.1', new p.InfoAccess({ accessDescriptions: [
      new p.AccessDescription({ accessMethod: '1.3.6.1.5.5.7.48.1', accessLocation: new p.GeneralName({ type: 6, value: `${opts.publicURL}/ocsp` }) }),
      new p.AccessDescription({ accessMethod: '1.3.6.1.5.5.7.48.2', accessLocation: new p.GeneralName({ type: 6, value: `${opts.publicURL}/ca/issuer.der` }) }),
    ] }).toSchema()));
    c.extensions.push(ext('2.5.29.31', new p.CRLDistributionPoints({ distributionPoints: [new p.DistributionPoint({ distributionPoint: [new p.GeneralName({ type: 6, value: `${opts.publicURL}/crl` })] })] }).toSchema()));
  }
  await c.sign(opts.signingKey, 'SHA-256');
  return c;
}
export const certPEM = (c: p.Certificate) => pem(c.toSchema(true).toBER(false), 'CERTIFICATE');
export interface Env {
  DB: D1Database; PUBLIC_URL: string; TSA_POLICY_OID: string; MAX_VALIDITY_DAYS: string;
  ROOT_CERT: string; CA_CERT: string; CA_KEY: string; TSA_CERT: string; TSA_KEY: string;
  OCSP_CERT: string; OCSP_KEY: string; ADMIN_TOKEN: string;
  TSA_FAKE?: string; TSA_CUSTOM_TOKEN?: string; TSA_CUSTOM_TOKEN_REQUIRED?: string; TSA_LEGACY?: string;
  PKI_MASTER_KEY?: string;
}
export interface Context {
  root: p.Certificate; ca: p.Certificate; tsa: p.Certificate; ocsp: p.Certificate;
  caKey: CryptoKey; tsaKey: CryptoKey; ocspKey: CryptoKey;
}
const contexts = new WeakMap<object, Promise<Context>>();
export async function context(env: Env): Promise<Context> {
  let result = contexts.get(env);
  if (!result) {
    result = (async () => {
      const root = cert(env.ROOT_CERT), ca = cert(env.CA_CERT), tsa = cert(env.TSA_CERT), ocsp = cert(env.OCSP_CERT);
      if (!await root.verify(root) || !await ca.verify(root) || !await tsa.verify(ca) || !await ocsp.verify(ca)) throw new Error('Invalid service certificate chain');
      for (const [child,parent] of [[ca,root],[tsa,ca],[ocsp,ca]]) {
        if (child.notBefore.value >= child.notAfter.value || child.notBefore.value < parent.notBefore.value || child.notAfter.value > parent.notAfter.value) throw new Error('Certificate validity outside issuer interval');
      }
      if (root.notBefore.value >= root.notAfter.value) throw new Error('Invalid root validity interval');
      for (const service of [tsa, ocsp]) {
        const expected = service === tsa ? OID.tsa : OID.ocsp;
        const eku = service.extensions?.find(e => e.extnID === '2.5.29.37');
        if (!eku || (expected === OID.tsa && !eku.critical) || new p.ExtKeyUsage({ schema: decode(eku.extnValue.valueBlock.valueHexView.slice().buffer) }).keyPurposes.join(',') !== expected) throw new Error('Invalid service EKU');
      }
      for (const authority of [root, ca]) {
        const bc = authority.extensions?.find(e => e.extnID === '2.5.29.19');
        if (!bc || !new p.BasicConstraints({ schema: decode(bc.extnValue.valueBlock.valueHexView.slice().buffer) }).cA) throw new Error('Invalid CA constraints');
      }
      const [caKey, tsaKey, ocspKey] = await Promise.all([privateKey(env.CA_KEY), privateKey(env.TSA_KEY), privateKey(env.OCSP_KEY)]);
      for (const [certificate, key] of [[ca, caKey], [tsa, tsaKey], [ocsp, ocspKey]] as const) {
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, challenge);
        const publicKey = await crypto.subtle.importKey('spki', certificate.subjectPublicKeyInfo.toSchema().toBER(false), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
        if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, signature, challenge)) throw new Error('Service key mismatch');
      }
      return { root, ca, tsa, ocsp, caKey, tsaKey, ocspKey };
    })();
    contexts.set(env, result);
    result.catch(() => contexts.delete(env));
  }
  const ctx = await result;
  const now = Date.now();
  for (const c of [ctx.root, ctx.ca]) if (now < c.notBefore.value.getTime() || now >= c.notAfter.value.getTime()) throw new Error('CA certificate outside validity');
  return ctx;
}
export interface CertificateRow {
  serial: string; pem: string; subject: string; profile: string; not_before: string; not_after: string;
  status: 'good' | 'revoked'; revoked_at: string | null; revocation_reason: number | null; created_at: string;
}
export function insertCertificate(db: D1Database, c: p.Certificate, profile: Profile): D1PreparedStatement {
  return db.prepare('INSERT INTO certificates (serial,pem,subject,profile,not_before,not_after,created_at) VALUES (?,?,?,?,?,?,?)')
    .bind(serial(c.serialNumber), certPEM(c), commonName(c.subject), profile, c.notBefore.value.toISOString(), c.notAfter.value.toISOString(), new Date().toISOString());
}
export function audit(db: D1Database, action: string, id: string | null, detail: string): D1PreparedStatement {
  return db.prepare('INSERT INTO audit (action,serial,at,detail) VALUES (?,?,?,?)').bind(action, id, new Date().toISOString(), detail);
}
export async function assertServiceActive(env: Env, certificate: p.Certificate): Promise<void> {
  if (Date.now() < certificate.notBefore.value.getTime() || Date.now() >= certificate.notAfter.value.getTime()) throw new Error('Service certificate outside validity');
  const row = await env.DB.prepare('SELECT pem,status FROM certificates WHERE serial=?').bind(serial(certificate.serialNumber)).first<{pem:string;status:string}>();
  if (!row || row.status !== 'good' || row.pem !== certPEM(certificate)) throw new Error('Service certificate unavailable or revoked');
}
