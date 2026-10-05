import { timingSafeEqual } from 'node:crypto';
import { a, p, context, decode, unpem, makeCert, cn, commonName, serial, certPEM, insertCertificate, audit, assertServiceActive, digest, ext, type Env, type CertificateRow } from './pki';
import { timestamp, failure } from './timestamp';
import { authenticode } from './authenticode';
import { ocsp, ocspError } from './ocsp';
import { adminHTML } from './ui';
import adminJS from '../generated/admin-client.js.txt';
import { tsaHTML } from './tsa-ui';
import tsaJS from '../generated/tsa-client.js.txt';
import { setupHTML } from './setup-ui';
import setupScript from '../generated/setup-client.js.txt';
import { runtimeEnv, setupStatus, initialize, renewService, AlreadyInitialized, InvalidServiceConfiguration, type ServiceOptions } from './storage';
import { parseCertificateDate } from './initialize';

class HttpError extends Error { constructor(public status: number, message: string) { super(message); } }
function json(value: unknown, status = 200): Response { return Response.json(value, { status, headers: { 'Cache-Control': 'no-store' } }); }
function binary(data: ArrayBuffer, type: string): Response { return new Response(data, { headers: { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } }); }
function page(value: string, type: 'html' | 'javascript'): Response {
  return new Response(value, { headers: {
    'Content-Type': type === 'html' ? 'text/html; charset=utf-8' : 'application/javascript; charset=utf-8', 'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'", 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
  } });
}
async function body(req: Request): Promise<ArrayBuffer> {
  if (Number(req.headers.get('Content-Length')) > 65536) throw new HttpError(413, 'Request too large');
  const reader = req.body?.getReader();
  if (!reader) throw new HttpError(400, 'Missing body');
  const chunks: Uint8Array[] = []; let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > 65536) { await reader.cancel(); throw new HttpError(413, 'Request too large'); }
    chunks.push(value);
  }
  const data = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.length; }
  return data.buffer;
}
function authorize(req: Request, env: Env): void {
  if (!env.ADMIN_TOKEN || env.ADMIN_TOKEN.length < 32) throw new HttpError(503, 'Admin not configured');
  const expected = new TextEncoder().encode(`Bearer ${env.ADMIN_TOKEN}`);
  const supplied = new TextEncoder().encode(req.headers.get('Authorization') ?? '');
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) throw new HttpError(401, 'Unauthorized');
}
async function requestJSON(req: Request): Promise<Record<string, unknown>> {
  if (req.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json') throw new HttpError(415, 'Expected application/json');
  try {
    const obj = JSON.parse(new TextDecoder().decode(await body(req)));
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new Error();
    return obj;
  } catch (e) { if (e instanceof HttpError) throw e; throw new HttpError(400, 'Invalid JSON'); }
}
async function issue(req: Request, env: Env): Promise<Response> {
  const input = await requestJSON(req);
  const { csr, profile, days = 90 } = input;
  if (typeof csr !== 'string' || !['code-signing', 'server', 'client'].includes(String(profile))) throw new HttpError(400, 'Expected csr and profile: code-signing/server/client');
  const max = Number(env.MAX_VALIDITY_DAYS);
  if (!Number.isSafeInteger(max) || max < 1) throw new HttpError(503, 'MAX_VALIDITY_DAYS must be a positive safe integer');
  let notBefore: Date | undefined, notAfter: Date | undefined;
  if (input.notBefore !== undefined || input.notAfter !== undefined) {
    if (typeof input.notBefore !== 'string' || typeof input.notAfter !== 'string' || input.days !== undefined) throw new HttpError(400, 'Provide both notBefore and notAfter, without days');
    try { notBefore = parseCertificateDate(input.notBefore); notAfter = parseCertificateDate(input.notAfter); }
    catch (error) { throw new HttpError(400,error instanceof Error ? error.message : 'Invalid UTC dates'); }
    if (notAfter.getTime() <= notBefore.getTime() || notAfter.getTime()-notBefore.getTime() > max*86400000) throw new HttpError(400, `Validity interval must be positive and at most ${max} days`);
  }
  if (!notBefore && (!Number.isInteger(days) || Number(days) < 1 || Number(days) > max)) throw new HttpError(400, `days must be between 1 and ${max}`);
  let parsed: p.CertificationRequest;
  try {
    parsed = new p.CertificationRequest({ schema: decode(unpem(csr, 'CERTIFICATE REQUEST')) });
    if (parsed.version !== 0 || !await parsed.verify()) throw new Error('Invalid CSR signature');
    const spki = parsed.subjectPublicKeyInfo;
    if (spki.algorithm.algorithmId === '1.2.840.113549.1.1.1') {
      const key = new p.RSAPublicKey({ schema: decode(spki.subjectPublicKey.valueBlock.valueHexView.slice().buffer) });
      const modulus = key.modulus.valueBlock.valueHexView;
      const bits = (modulus.length - (modulus[0] === 0 ? 1 : 0)) * 8;
      if (bits < 2048 || bits > 4096 || key.publicExponent.valueBlock.valueDec !== 65537) throw new Error('RSA must be 2048–4096 bits with exponent 65537');
    } else if (spki.algorithm.algorithmId === '1.2.840.10045.2.1') {
      const curve = spki.algorithm.algorithmParams;
      if (!(curve instanceof a.ObjectIdentifier) || !['1.2.840.10045.3.1.7', '1.3.132.0.34'].includes(curve.valueBlock.toString())) throw new Error('Only P-256/P-384 supported');
    } else throw new Error('Only RSA or EC keys supported');
    commonName(parsed.subject);
  } catch (e) { throw new HttpError(400, e instanceof Error ? e.message : 'Invalid CSR'); }
  const ctx = await context(env);
  await assertServiceActive(env, ctx.ca);
  let certificate: p.Certificate;
  try {
    // CSR extensions are deliberately not copied. The authenticated caller supplies the allowed SANs.
    certificate = await makeCert({ subject: cn(commonName(parsed.subject)), publicKey: parsed.subjectPublicKeyInfo, issuer: ctx.ca, signingKey: ctx.caKey, profile: profile as 'server' | 'client' | 'code-signing', days: Number(days), publicURL: env.PUBLIC_URL, dnsNames: profile === 'server' ? input.dnsNames as string[] : undefined,notBefore,notAfter });
  } catch (e) { throw new HttpError(400, e instanceof Error ? e.message : 'Invalid certificate parameters'); }
  await env.DB.batch([insertCertificate(env.DB, certificate, profile as 'server' | 'client' | 'code-signing'), audit(env.DB, 'issue', serial(certificate.serialNumber), JSON.stringify({ profile }))]);
  return json({ serial: serial(certificate.serialNumber), certificate: certPEM(certificate), chain: certPEM(ctx.ca) + certPEM(ctx.root), notBefore:certificate.notBefore.value.toISOString(), notAfter: certificate.notAfter.value.toISOString() }, 201);
}
async function crl(env: Env): Promise<Response> {
  const ctx = await context(env); await assertServiceActive(env, ctx.ca);
  const rows = await env.DB.prepare("SELECT * FROM certificates WHERE status='revoked'").all<CertificateRow>();
  if (rows.results.length > 10000) throw new HttpError(503, 'CRL size limit reached; partition CA before continuing');
  const now = new Date();
  const count = await env.DB.prepare('UPDATE crl_sequence SET number=number+1 WHERE id=1 RETURNING number').first<{number:number}>();
  if (!count) throw new HttpError(503, 'CRL counter unavailable');
  const result = new p.CertificateRevocationList({ version: 1, issuer: ctx.ca.subject,
    thisUpdate: new p.Time({ value: now }), nextUpdate: new p.Time({ value: new Date(Math.min(now.getTime() + 300000, ctx.ca.notAfter.value.getTime())) }),
    revokedCertificates: rows.results.map(row => new p.RevokedCertificate({ userCertificate: new a.Integer({ valueHex: Uint8Array.from((row.serial.length % 2 ? '0' + row.serial : row.serial).match(/../g)!, v => parseInt(v, 16)).buffer }), revocationDate: new p.Time({ value: new Date(row.revoked_at!) }), crlEntryExtensions: new p.Extensions({ extensions: [new p.Extension({ extnID: '2.5.29.21', extnValue: new a.Enumerated({ value: row.revocation_reason ?? 0 }).toBER(false) })] }) })),
    crlExtensions: new p.Extensions({ extensions: [
      ext('2.5.29.20', new a.Integer({ value: count.number })),
      ext('2.5.29.35', new p.AuthorityKeyIdentifier({ keyIdentifier: new a.OctetString({ valueHex: await digest(ctx.ca.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView.slice().buffer, 'SHA-1') }) }).toSchema()),
    ] }),
  });
  await result.sign(ctx.caKey, 'SHA-256');
  return binary(result.toSchema(true).toBER(false), 'application/pkix-crl');
}
async function route(req: Request, env: Env): Promise<Response> {
  const deploymentEnv = env;
  const url = new URL(req.url), path = url.pathname;
  if (req.method === 'GET' && ['/setup', '/setup.js'].includes(path)) return page(path === '/setup' ? setupHTML : setupScript, path === '/setup' ? 'html' : 'javascript');
  if (req.method === 'GET' && path === '/api/setup/status') return json(await setupStatus(env));
  if (req.method === 'POST' && path === '/api/setup') {
    if (req.headers.get('Origin') && req.headers.get('Origin') !== url.origin) throw new HttpError(403, 'Origin mismatch');
    const master = env.PKI_MASTER_KEY ?? '';
    if (!/^[0-9a-fA-F]{64}$/.test(master)) throw new HttpError(503, 'Set PKI_MASTER_KEY to a random 64-character hexadecimal secret first');
    const expected = new TextEncoder().encode('Bearer ' + master), supplied = new TextEncoder().encode(req.headers.get('Authorization') ?? '');
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) throw new HttpError(401, 'Unauthorized initialization request');
    const input = await requestJSON(req);
    if (Object.keys(input).length !== 2 || Object.keys(input).some(key => !['publicURL','config'].includes(key))) throw new HttpError(400, 'Unexpected setup fields');
    if (input.publicURL !== env.PUBLIC_URL) throw new HttpError(400, 'Public URL mismatch');
    try { await initialize(env, input.config); }
    catch (error) { if (error instanceof AlreadyInitialized) throw new HttpError(409, error.message); throw new HttpError(400, error instanceof Error ? error.message : 'Invalid PKI configuration'); }
    return json({ initialized: true, admin: '/admin' }, 201);
  }
  const effective = await runtimeEnv(env);
  if (!effective) {
    if (req.method === 'GET' && ['/', '/admin', '/admin/tsa'].includes(path)) return new Response(null, { status: 302, headers: { Location: '/setup', 'Cache-Control': 'no-store' } });
    if (req.method === 'GET' && path === '/health') return json({ status: 'uninitialized', setup: '/setup' }, 503);
    throw new HttpError(503, 'PKI not initialized; open /setup');
  }
  env = effective;
  if (req.method === 'GET' && path === '/') return json({ service: 'Signcert private PKI', timestamp: '/tsa', ocsp: '/ocsp', crl: '/crl', admin: '/admin', protocols: ['RFC 3161', 'RFC 6960'], customTimeEnabled: env.TSA_FAKE === 'true' });
  if (req.method === 'GET' && path === '/health') {
    try { const ctx = await context(env); await env.DB.prepare('SELECT 1').first(); for (const c of [ctx.ca, ctx.tsa, ctx.ocsp]) await assertServiceActive(env, c); return json({ status: 'ready' }); }
    catch { return json({ status: 'unavailable' }, 503); }
  }
  if (req.method === 'GET' && ['/admin', '/admin.js'].includes(path)) return page(path === '/admin' ? adminHTML : adminJS, path === '/admin' ? 'html' : 'javascript');
  if (req.method === 'GET' && ['/admin/tsa', '/tsa-admin.js'].includes(path)) return page(path === '/admin/tsa' ? tsaHTML : tsaJS,path === '/admin/tsa' ? 'html' : 'javascript');
  if (req.method === 'GET' && /^\/ca\/(root|issuer|tsa|ocsp)\.(pem|der|cer)$/.test(path)) {
    const ctx = await context(env); const [, name, format] = path.match(/^\/ca\/(root|issuer|tsa|ocsp)\.(pem|der|cer)$/)!;
    const certificate = name === 'issuer' ? ctx.ca : ctx[name as 'root' | 'tsa' | 'ocsp'];
    if (format === 'pem') return new Response(certPEM(certificate), { headers: { 'Content-Type': 'application/x-pem-file', 'Cache-Control': 'no-store' } });
    const response = binary(certificate.toSchema(true).toBER(false), 'application/pkix-cert');
    if (format === 'cer') response.headers.set('Content-Disposition',`attachment; filename="${name}.cer"`);
    return response;
  }
  if (req.method === 'GET' && path === '/crl') return crl(env);
  const customMatch = path.match(/^\/(?:tsa\/)?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z?)\/?$/);
  if (req.method === 'POST' && (['/', '/tsa', '/tsa/'].includes(path) || customMatch)) {
    let customTime: Date | undefined;
    if (customMatch) {
      if (env.TSA_FAKE !== 'true') throw new HttpError(403, 'Custom time disabled');
      if (env.TSA_CUSTOM_TOKEN_REQUIRED !== 'false') {
        const token = env.TSA_CUSTOM_TOKEN;
        if (!token || token.length < 32) throw new HttpError(503, 'Custom timestamp token not configured');
        const supplied = req.headers.get('X-TSA-Token') ?? url.searchParams.get('token') ?? '';
        const expectedBytes = new TextEncoder().encode(token), suppliedBytes = new TextEncoder().encode(supplied);
        if (suppliedBytes.length !== expectedBytes.length || !timingSafeEqual(suppliedBytes, expectedBytes)) throw new HttpError(401, 'Unauthorized custom timestamp request');
      }
      const text = customMatch[1].replace(/Z$/, '');
      customTime = new Date(text + 'Z');
      if (!Number.isFinite(customTime.getTime()) || customTime.toISOString() !== (text.includes('.') ? text : text + '.000') + 'Z') throw new HttpError(400, 'Invalid UTC date');
    }
    const contentType = req.headers.get('Content-Type')?.split(';')[0].trim();
    if (contentType !== 'application/timestamp-query' && contentType !== 'application/octet-stream') throw new HttpError(415, 'Expected application/timestamp-query or application/octet-stream');
    const data = await body(req);
    if (contentType === 'application/octet-stream') {
      if (env.TSA_LEGACY !== 'true') throw new HttpError(403, 'Legacy Authenticode disabled');
      try { return new Response(await authenticode(data, env, await context(env), customTime), { headers: { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store' } }); }
      catch (error) {
        console.error('Authenticode timestamp unavailable',{requestBytes:data.byteLength,reason:(error instanceof Error ? error.message : 'Unknown error').slice(0,200)});
        throw new HttpError(400, 'Invalid or unavailable Authenticode timestamp request');
      }
    }
    try { return binary(await timestamp(data, env, await context(env), customTime), 'application/timestamp-reply'); }
    catch (e) { console.error('Timestamp unavailable', e instanceof Error ? e.message : 'failure'); return binary(failure(25, 'Service unavailable'), 'application/timestamp-reply'); }
  }
  if (path === '/ocsp' || path.startsWith('/ocsp/')) {
    let data: ArrayBuffer;
    if (req.method === 'POST' && path === '/ocsp') {
      if (req.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/ocsp-request') throw new HttpError(415, 'Expected application/ocsp-request');
      data = await body(req);
    } else if (req.method === 'GET' && path.startsWith('/ocsp/')) {
      try { const encoded = decodeURIComponent(path.slice(6)); if (encoded.length > 8192 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw new Error(); data = Uint8Array.from(atob(encoded), c => c.charCodeAt(0)).buffer; }
      catch { return binary(ocspError(1), 'application/ocsp-response'); }
    } else throw new HttpError(405, 'Method not allowed');
    try { return binary(await ocsp(data, env, await context(env)), 'application/ocsp-response'); }
    catch (e) { console.error('OCSP unavailable', e instanceof Error ? e.message : 'failure'); return binary(ocspError(3), 'application/ocsp-response'); }
  }
  if (path.startsWith('/api/')) {
    authorize(req, env);
    if (path === '/api/services/tsa' && req.method === 'GET') {
      const ctx = await context(env);
      const currentSerial = serial(ctx.tsa.serialNumber);
      const row = await env.DB.prepare('SELECT status FROM certificates WHERE serial=?').bind(currentSerial).first<{status:string}>();
      return json({mode:(await setupStatus(deploymentEnv)).mode,serial:currentSerial,subject:commonName(ctx.tsa.subject),status:row?.status ?? 'unknown',notBefore:ctx.tsa.notBefore.value.toISOString(),notAfter:ctx.tsa.notAfter.value.toISOString(),certificate:certPEM(ctx.tsa),chain:certPEM(ctx.ca)+certPEM(ctx.root),issuer:{subject:commonName(ctx.ca.subject),notBefore:ctx.ca.notBefore.value.toISOString(),notAfter:ctx.ca.notAfter.value.toISOString()},endpoint:env.PUBLIC_URL+'/tsa',customTimeEnabled:env.TSA_FAKE==='true',customTokenRequired:env.TSA_CUSTOM_TOKEN_REQUIRED!=='false',policy:env.TSA_POLICY_OID});
    }
    const renewal = path.match(/^\/api\/services\/(tsa|ocsp)\/renew$/);
    if (renewal && req.method === 'POST') {
      const input = await requestJSON(req);
      const allowed = renewal[1] === 'tsa' ? ['subject','notBefore','notAfter','expectedSerial'] : [];
      if (Object.keys(input).some(key=>!allowed.includes(key) || typeof input[key] !== 'string')) throw new HttpError(400,'Unexpected service configuration fields');
      try { return json(await renewService(deploymentEnv, renewal[1] as 'tsa' | 'ocsp',input as ServiceOptions),201); }
      catch (error) { if (error instanceof AlreadyInitialized) throw new HttpError(409,error.message); if (error instanceof InvalidServiceConfiguration) throw new HttpError(400,error.message); throw error; }
    }
    if (path === '/api/certificates' && req.method === 'POST') return issue(req, env);
    if (path === '/api/certificates' && req.method === 'GET') {
      const limit = Math.min(Math.max(Number(url.searchParams.get('limit')) || 50, 1), 200);
      const offset = Math.max(Number(url.searchParams.get('offset')) || 0, 0);
      if (!Number.isInteger(limit) || !Number.isInteger(offset)) throw new HttpError(400, 'Invalid pagination');
      const rows = await env.DB.prepare('SELECT * FROM certificates ORDER BY created_at DESC,serial LIMIT ? OFFSET ?').bind(limit, offset).all<CertificateRow>();
      return json({ certificates: rows.results, limit, offset });
    }
    const match = path.match(/^\/api\/certificates\/([0-9a-f]{1,40})(\/revoke)?$/);
    if (match) {
      const id = match[1].replace(/^0+/, '') || '0';
      const row = await env.DB.prepare('SELECT * FROM certificates WHERE serial=?').bind(id).first<CertificateRow>();
      if (!row) throw new HttpError(404, 'Certificate not found');
      if (req.method === 'GET' && !match[2]) return json(row);
      if (req.method === 'POST' && match[2]) {
        const input = await requestJSON(req); const reason = input.reason ?? 0;
        if (!Number.isInteger(reason) || ![0, 1, 2, 3, 4, 5, 9, 10].includes(Number(reason))) throw new HttpError(400, 'Invalid permanent revocation reason');
        const at = new Date().toISOString();
        // Audit and status transition are in the same D1 transaction. Repeated revocation preserves its first date.
        await env.DB.batch([
          env.DB.prepare("INSERT INTO audit (action,serial,at,detail) SELECT 'revoke',serial,?,? FROM certificates WHERE serial=? AND status='good'").bind(at, JSON.stringify({ reason }), id),
          env.DB.prepare("UPDATE certificates SET status='revoked',revoked_at=?,revocation_reason=? WHERE serial=? AND status='good'").bind(at, Number(reason), id),
        ]);
        return json(await env.DB.prepare('SELECT * FROM certificates WHERE serial=?').bind(id).first());
      }
    }
    if (path === '/api/audit' && req.method === 'GET') return json((await env.DB.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 200').all()).results);
  }
  throw new HttpError(404, 'Not found');
}
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    try { return await route(req, env); }
    catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error('Request failed', e instanceof Error ? e.message : 'failure');
      return json({ error: 'Service unavailable' }, 503);
    }
  },
};
