import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { X509Certificate } from 'node:crypto';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { a, p, cn, rsaKeys, makeCert, certPEM, pem, unpem, digest, decode, base64, OID, serial, insertCertificate } from '../src/pki';
import { workerModules } from './worker-modules';

let mf: Miniflare, db: D1Database, root: p.Certificate, ca: p.Certificate, tsa: p.Certificate, responder: p.Certificate, csrPEM: string;
const token = 'a'.repeat(64), customToken = 'b'.repeat(64);
const original = new TextEncoder().encode('Signcert integration fixture').buffer;
before(async () => {
  const rootKeys = await rsaKeys(), caKeys = await rsaKeys(), tsaKeys = await rsaKeys(), ocspKeys = await rsaKeys(), clientKeys = await rsaKeys();
  const pub = async (key: CryptoKey) => { const value = new p.PublicKeyInfo(); await value.importKey(key); return value; };
  root = await makeCert({ subject: cn('Test Root'), publicKey: await pub(rootKeys.publicKey), signingKey: rootKeys.privateKey, profile: 'root', days: 3650 });
  ca = await makeCert({ subject: cn('Test Issuer'), publicKey: await pub(caKeys.publicKey), signingKey: rootKeys.privateKey, issuer: root, profile: 'issuer', days: 365 });
  tsa = await makeCert({ subject: cn('Test TSA'), publicKey: await pub(tsaKeys.publicKey), signingKey: caKeys.privateKey, issuer: ca, profile: 'tsa', days: 90 });
  responder = await makeCert({ subject: cn('Test OCSP'), publicKey: await pub(ocspKeys.publicKey), signingKey: caKeys.privateKey, issuer: ca, profile: 'ocsp', days: 90 });
  const csr = new p.CertificationRequest({ version: 0, subject: cn('Test App'), subjectPublicKeyInfo: await pub(clientKeys.publicKey) });
  await csr.sign(clientKeys.privateKey, 'SHA-256'); csrPEM = pem(csr.toSchema().toBER(false), 'CERTIFICATE REQUEST');
  const bindings = {
    PUBLIC_URL: 'https://pki.example.com', TSA_POLICY_OID: '1.3.6.1.4.1.55555.1.1', MAX_VALIDITY_DAYS: '365', TSA_FAKE: 'true', TSA_LEGACY: 'true', ADMIN_TOKEN: token, TSA_CUSTOM_TOKEN: customToken,
    ROOT_CERT: certPEM(root), CA_CERT: certPEM(ca), TSA_CERT: certPEM(tsa), OCSP_CERT: certPEM(responder),
    CA_KEY: pem(await crypto.subtle.exportKey('pkcs8', caKeys.privateKey), 'PRIVATE KEY'),
    TSA_KEY: pem(await crypto.subtle.exportKey('pkcs8', tsaKeys.privateKey), 'PRIVATE KEY'),
    OCSP_KEY: pem(await crypto.subtle.exportKey('pkcs8', ocspKeys.privateKey), 'PRIVATE KEY'),
  };
  mf = new Miniflare(convertV4MiniflareOptions({ modules: await workerModules(), compatibilityDate: '2026-10-01', compatibilityFlags: ['nodejs_compat'], bindings, d1Databases: { DB: 'test-signcert' } }));
  db = await mf.getD1Database('DB') as unknown as D1Database;
  const sql = await readFile('migrations/0001_pki.sql', 'utf8');
  await db.batch(sql.split(';').filter(v => v.trim()).map(v => db.prepare(v)));
  await db.batch([insertCertificate(db, ca, 'issuer'), insertCertificate(db, tsa, 'tsa'), insertCertificate(db, responder, 'ocsp')]);
});
after(async () => { await mf?.dispose(); });
async function call(path: string, method = 'GET', input?: unknown, auth = true) {
  return mf.dispatchFetch('https://pki.example.com' + path, { method, headers: { ...(auth ? { Authorization: 'Bearer ' + token } : {}), ...(input ? { 'Content-Type': 'application/json' } : {}) }, ...(input ? { body: JSON.stringify(input) } : {}) });
}
async function issue(profile = 'code-signing', extra = {}) {
  const r = await call('/api/certificates', 'POST', { csr: csrPEM, profile, ...extra });
  assert.equal(r.status, 201, await r.clone().text());
  return await r.json() as {serial:string;certificate:string;chain:string};
}
async function tsRequest(overrides: Partial<p.TimeStampReq> = {}) {
  return new p.TimeStampReq({ version: 1, messageImprint: new p.MessageImprint({ hashAlgorithm: new p.AlgorithmIdentifier({ algorithmId: OID.sha256 }), hashedMessage: new a.OctetString({ valueHex: await digest(original) }) }), nonce: new a.Integer({ value: 12345 }), certReq: true, ...overrides });
}
async function sendTS(req: p.TimeStampReq | ArrayBuffer, path = '/tsa') {
  const r = await mf.dispatchFetch('https://pki.example.com' + path, { method: 'POST', headers: { 'Content-Type': 'application/timestamp-query' }, body: req instanceof p.TimeStampReq ? req.toSchema().toBER(false) : req });
  return { response: r, parsed: r.status === 200 ? new p.TimeStampResp({ schema: decode(await r.arrayBuffer()) }) : undefined };
}
function signed(resp: p.TimeStampResp) { return new p.SignedData({ schema: resp.timeStampToken!.content }); }
async function ocspFor(certificate: p.Certificate, issuer = ca, nonce = true, get = false) {
  const req = new p.OCSPRequest(); await req.createForCertificate(certificate, { issuerCertificate: issuer, hashAlgorithm: 'SHA-1' });
  if (nonce) req.tbsRequest.requestExtensions = [new p.Extension({ extnID: OID.nonce, extnValue: new a.OctetString({ valueHex: new Uint8Array([1,2,3,4]).buffer }).toBER(false) })];
  const der = req.toSchema(true).toBER(false);
  const r = get ? await mf.dispatchFetch('https://pki.example.com/ocsp/' + encodeURIComponent(Buffer.from(der).toString('base64'))) : await mf.dispatchFetch('https://pki.example.com/ocsp', { method: 'POST', headers: { 'Content-Type': 'application/ocsp-request' }, body: der });
  const response = new p.OCSPResponse({ schema: decode(await r.arrayBuffer()) });
  assert.equal(response.responseStatus.valueBlock.valueDec, 0);
  const basic = new p.BasicOCSPResponse({ schema: decode(response.responseBytes!.response.valueBlock.valueHexView.slice().buffer) });
  assert.equal(await basic.verify({ trustedCerts: [root], issuerCerts: [ca], ...(issuer !== ca ? { trustedResponders: [responder] } : {}) }), true);
  if (nonce) assert.deepEqual(basic.tbsResponseData.responseExtensions![0].extnValue.valueBlock.valueHexView, req.tbsRequest.requestExtensions![0].extnValue.valueBlock.valueHexView);
  assert.ok(basic.tbsResponseData.responses[0].nextUpdate!.getTime() - basic.tbsResponseData.responses[0].thisUpdate.getTime() <= 300000);
  return basic.tbsResponseData.responses[0];
}
test('Worker readiness checks secrets, chain, keys, D1 and service status', async () => { assert.equal((await call('/health')).status, 200); });
test('admin APIs require authentication and reject oversized bodies', async () => {
  assert.equal((await call('/api/certificates', 'GET', undefined, false)).status, 401);
  assert.equal((await call('/api/certificates', 'POST', { csr: 'x'.repeat(70000), profile: 'client' })).status, 413);
});
test('CSR issuance produces a verifiable end entity, bounded validity and AIA/CRL', async () => {
  const result = await issue(); const certificate = new p.Certificate({ schema: decode(unpem(result.certificate, 'CERTIFICATE')) });
  // Node/OpenSSL verifies X.509 independently of PKI.js.
  assert.equal(new X509Certificate(result.certificate).verify(new X509Certificate(certPEM(ca)).publicKey), true);
  assert.equal(await certificate.verify(ca), true);
  assert.equal(certificate.extensions!.find(e => e.extnID === '2.5.29.19')!.parsedValue.cA, false);
  assert.equal(certificate.extensions!.find(e => e.extnID === '2.5.29.37')!.parsedValue.keyPurposes[0], '1.3.6.1.5.5.7.3.3');
  assert.ok(certificate.extensions!.some(e => e.extnID === '1.3.6.1.5.5.7.1.1'));
  assert.ok(certificate.extensions!.some(e => e.extnID === '2.5.29.31'));
  assert.equal((await call('/api/certificates/' + result.serial)).status, 200);
});
test('issuer rejects CA profile, invalid CSR, excessive validity and invalid DNS SANs', async () => {
  for (const input of [{ csr: csrPEM, profile: 'root' }, { csr: 'bad', profile: 'client' }, { csr: csrPEM, profile: 'client', days: 366 }, { csr: csrPEM, profile: 'server', dnsNames: ['localhost'] }]) assert.equal((await call('/api/certificates', 'POST', input)).status, 400);
  const result = await issue('server', { dnsNames: ['app.example.com'] });
  assert.equal(new X509Certificate(result.certificate).checkHost('app.example.com'), 'app.example.com');
});
test('RFC 3161 CMS signature, ESS certificate binding, nonce and imprint verify', async () => {
  const result = await sendTS(await tsRequest()); assert.equal(result.parsed!.status.status, 0);
  const sd = signed(result.parsed!);
  assert.equal(await sd.verify({ signer: 0, data: original, checkChain: true, trustedCerts: [root] }), true);
  const info = new p.TSTInfo({ schema: decode(sd.encapContentInfo.eContent!.getValue()) });
  assert.equal(info.nonce!.valueBlock.valueDec, 12345);
  assert.ok(Math.abs(info.genTime.getTime() - Date.now()) < 10000);
  const attr = sd.signerInfos[0].signedAttrs!.attributes.find(v => v.type === '1.2.840.113549.1.9.16.2.47')!;
  const certHash = (attr.values[0] as a.Sequence).valueBlock.value[0] as a.Sequence;
  const value = ((certHash.valueBlock.value[0] as a.Sequence).valueBlock.value[0] as a.OctetString).getValue();
  assert.deepEqual(new Uint8Array(value), new Uint8Array(await digest(tsa.toSchema(true).toBER(false))));
  assert.equal(sd.version, 3);
});
test('RFC 3161 rejects unknown algorithms, bad lengths, policy, extensions and malformed DER', async () => {
  const cases = [
    await tsRequest({ version: 2 }),
    await tsRequest({ messageImprint: new p.MessageImprint({ hashAlgorithm: new p.AlgorithmIdentifier({ algorithmId: '1.2.3.4' }), hashedMessage: new a.OctetString({ valueHex: new Uint8Array(32).buffer }) }) }),
    await tsRequest({ messageImprint: new p.MessageImprint({ hashAlgorithm: new p.AlgorithmIdentifier({ algorithmId: OID.sha256 }), hashedMessage: new a.OctetString({ valueHex: new Uint8Array(31).buffer }) }) }),
    await tsRequest({ reqPolicy: '1.2.3' }),
    await tsRequest({ extensions: [new p.Extension({ extnID: '1.2.3', extnValue: new a.Null().toBER(false) })] }),
    new Uint8Array([0, 1, 2]).buffer,
  ];
  for (const req of cases) { const result = await sendTS(req); assert.equal(result.parsed!.status.status, 2); assert.ok(result.parsed!.status.failInfo); }
});
test('certReq=false omits certificates and SHA-384 imprint is retained', async () => {
  const req = await tsRequest({ certReq: false, messageImprint: new p.MessageImprint({ hashAlgorithm: new p.AlgorithmIdentifier({ algorithmId: OID.sha384 }), hashedMessage: new a.OctetString({ valueHex: await digest(original, 'SHA-384') }) }) });
  const result = await sendTS(req); const sd = signed(result.parsed!);
  assert.equal(sd.certificates?.length ?? 0, 0);
  const info = new p.TSTInfo({ schema: decode(sd.encapContentInfo.eContent!.getValue()) });
  assert.equal(info.messageImprint.hashAlgorithm.algorithmId, OID.sha384);
});
test('custom UTC timestamps support upstream path, require token and record actual request time', async () => {
  const req = await tsRequest();
  assert.equal((await sendTS(req, '/2020-01-01T00:00:00')).response.status, 401);
  assert.equal((await sendTS(req, '/2020-01-01T00:00:00/')).response.status, 401);
  assert.equal((await sendTS(req, '/tsa/2020-01-01T00:00:00/')).response.status, 401);
  assert.equal((await sendTS(req, '/2020-02-30T00:00:00?token=' + customToken)).response.status, 400);
  for (const path of ['/2020-01-01T00:00:00', '/2020-01-01T00:00:00/', '/tsa/2020-01-01T00:00:00Z', '/tsa/2020-01-01T00:00:00Z/']) {
    const result = await sendTS(req, path + '?token=' + customToken);
    assert.equal(result.parsed!.status.status, 0);
    const sd = signed(result.parsed!); const info = new p.TSTInfo({ schema: decode(sd.encapContentInfo.eContent!.getValue()) });
    assert.equal(info.genTime.toISOString(), '2020-01-01T00:00:00.000Z');
    const row = await db.prepare('SELECT * FROM timestamps WHERE serial=?').bind(serial(info.serialNumber)).first<{time_mode:string;received_at:string}>();
    assert.equal(row!.time_mode, 'custom'); assert.ok(Math.abs(Date.parse(row!.received_at) - Date.now()) < 10000);
  }
});
test('OCSP POST/GET verifies signatures and returns good, revoked, unknown, echoes nonce', async () => {
  const result = await issue(); const certificate = new p.Certificate({ schema: decode(unpem(result.certificate, 'CERTIFICATE')) });
  assert.equal((await ocspFor(certificate)).certStatus.idBlock.tagNumber, 0);
  assert.equal((await ocspFor(certificate, ca, true, true)).certStatus.idBlock.tagNumber, 0);
  assert.equal((await ocspFor(certificate, root)).certStatus.idBlock.tagNumber, 2);
  const unknown = new p.Certificate({ schema: certificate.toSchema(true) }); unknown.serialNumber = new a.Integer({ value: 999999 });
  assert.equal((await ocspFor(unknown)).certStatus.idBlock.tagNumber, 2);
  const first = await call('/api/certificates/' + result.serial + '/revoke', 'POST', { reason: 1 }); assert.equal(first.status, 200);
  const firstRow = await first.json() as {revoked_at:string};
  const second = await call('/api/certificates/' + result.serial + '/revoke', 'POST', { reason: 4 }); const secondRow = await second.json() as {revoked_at:string;revocation_reason:number};
  assert.equal(secondRow.revoked_at, firstRow.revoked_at); assert.equal(secondRow.revocation_reason, 1);
  assert.equal((await ocspFor(certificate)).certStatus.idBlock.tagNumber, 1);
  const audit = await db.prepare("SELECT COUNT(*) AS count FROM audit WHERE action='revoke' AND serial=?").bind(result.serial).first<{count:number}>();
  assert.equal(audit!.count, 1);
  const crlResponse = await call('/crl'); const crl = new p.CertificateRevocationList({ schema: decode(await crlResponse.arrayBuffer()) });
  assert.equal(await crl.verify({ issuerCertificate: ca }), true);
  assert.ok(crl.revokedCertificates!.some(c => serial(c.userCertificate) === result.serial));
});
test('bad OCSP DER returns malformedRequest', async () => {
  const response = await mf.dispatchFetch('https://pki.example.com/ocsp', { method: 'POST', headers: { 'Content-Type': 'application/ocsp-request' }, body: new Uint8Array([0,1,2]) });
  assert.equal(new p.OCSPResponse({ schema: decode(await response.arrayBuffer()) }).responseStatus.valueBlock.valueDec, 1);
});
test('legacy Authenticode returns signed CMS with current or custom signingTime', async () => {
  const request = new a.Sequence({ value: [new a.ObjectIdentifier({ value: '1.3.6.1.4.1.311.3.2.1' }), new a.Sequence({ value: [new a.ObjectIdentifier({ value: '1.2.840.113549.1.7.1' }), new a.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [new a.OctetString({ valueHex: original })] })] })] });
  for (const path of ['/tsa', '/tsa/', '/2020-01-01T00:00:00?token=' + customToken, '/2020-01-01T00:00:00/?token=' + customToken]) {
    const r = await mf.dispatchFetch('https://pki.example.com' + path, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: base64(request.toBER(false)) });
    assert.equal(r.status, 200);
    const content = new p.ContentInfo({ schema: decode(Uint8Array.from(atob(await r.text()), c => c.charCodeAt(0)).buffer) });
    const sd = new p.SignedData({ schema: content.content });
    assert.equal(await sd.verify({ signer: 0, checkChain: true, trustedCerts: [root] }), true);
    assert.deepEqual(new Uint8Array(sd.encapContentInfo.eContent!.getValue()), new Uint8Array(original));
    const time = sd.signerInfos[0].signedAttrs!.attributes.find(v => v.type === '1.2.840.113549.1.9.5')!.values[0] as a.UTCTime;
    if (path.includes('2020')) assert.equal(time.toDate().toISOString(), '2020-01-01T00:00:00.000Z');
  }
  const bad = await mf.dispatchFetch('https://pki.example.com/tsa', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: 'garbage' });
  assert.equal(bad.status, 400);
});
test('legacy Authenticode accepts the 411-byte Windows Base64 request with CRLF and trailing NUL',async () => {
  const payload=crypto.getRandomValues(new Uint8Array(256)).buffer;
  const request=new a.Sequence({value:[new a.ObjectIdentifier({value:'1.3.6.1.4.1.311.3.2.1'}),new a.Sequence({value:[new a.ObjectIdentifier({value:'1.2.840.113549.1.7.1'}),new a.Constructed({idBlock:{tagClass:3,tagNumber:0},value:[new a.OctetString({valueHex:payload})]})]})]});
  const plain=base64(request.toBER(false));
  const padded=plain.match(/.{1,64}/g)!.join('\r\n')+'\r\n\0';
  assert.equal(new TextEncoder().encode(padded).byteLength,411);
  const send=(body:string,path='/tsa')=>mf.dispatchFetch('https://pki.example.com'+path,{method:'POST',headers:{'Content-Type':'application/octet-stream'},body});
  for(const path of ['/tsa','/2022-11-03T21:14:19/?token='+customToken]) {
    const response=await send(padded,path);assert.equal(response.status,200,await response.clone().text());
    const content=new p.ContentInfo({schema:decode(Uint8Array.from(atob(await response.text()),c=>c.charCodeAt(0)).buffer)});
    const sd=new p.SignedData({schema:content.content});
    assert.equal(await sd.verify({signer:0,checkChain:true,trustedCerts:[root]}),true);
    assert.deepEqual(new Uint8Array(sd.encapContentInfo.eContent!.getValue()),new Uint8Array(payload));
    if(path.includes('2022')) {
      const time=sd.signerInfos[0].signedAttrs!.attributes.find(v=>v.type==='1.2.840.113549.1.9.5')!.values[0] as a.UTCTime;
      assert.equal(time.toDate().toISOString(),'2022-11-03T21:14:19.000Z');
    }
  }
  for(const malformed of [plain.slice(0,30)+'\0'+plain.slice(30),plain+'@',plain+'\0unexpected'])assert.equal((await send(malformed)).status,400);
});

test('revoked TSA fails closed while existing certificate status remains available', async () => {
  assert.equal((await call('/api/certificates/' + serial(tsa.serialNumber) + '/revoke', 'POST', { reason: 1 })).status, 200);
  assert.equal((await call('/health')).status, 503);
  assert.equal((await sendTS(await tsRequest())).parsed!.status.status, 2);
  assert.equal((await ocspFor(tsa)).certStatus.idBlock.tagNumber, 1);
});
