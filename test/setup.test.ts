import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { X509Certificate, createPrivateKey, createPublicKey } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { browserCSR, createPFX } from '../src/client-certificate';
import {subjectText,subjectFromText} from '../src/subject';
import { Miniflare, convertV4MiniflareOptions, type V4ModuleDefinition } from 'miniflare';
import { workerModules } from './worker-modules';
import { generateInitialization, initializationValidity, parseCertificateDate, type InitializationResult } from '../src/initialize';
import { decryptBackup, decryptJSON, vaultKey, type EncryptedJSON } from '../src/encryption';
import { a, p, decode, digest, OID, cert, cn, rsaKeys, pem, privateKey, certPEM, makeCert, serial, type Env } from '../src/pki';

const master = 'abcdef01'.repeat(8), backupPassword = 'integration-backup-password-2026';
let mf: Miniflare, db: D1Database, pending: InitializationResult, directory: string, modules: V4ModuleDefinition[];
let exportedPFX: ArrayBuffer, exportedCertificate: string;
const exportPassword = '测试-PFX-password-2026';
const fullSubject='Description = 皮卡丘公共服务测试根证书 RSA\nDescription = Pikachu Public Test Root RSA\nE = testca@certs.us.kg\nCN = Pikachu Test CA RSA\nOU = Pikachu Certification Authority\nO = Pikachu Trust Network CA\nC = CN';
function options(key = master, maxValidityDays = '365', customTokenRequired = 'true', customTimeEnabled = 'true') {
  return convertV4MiniflareOptions({ modules, compatibilityDate: '2026-10-01', compatibilityFlags: ['nodejs_compat'],
    bindings: { PKI_MASTER_KEY: key, PUBLIC_URL: 'https://pki.example.com', TSA_POLICY_OID: '1.3.6.1.4.1.55555.1.1', MAX_VALIDITY_DAYS: maxValidityDays, TSA_FAKE: customTimeEnabled, TSA_CUSTOM_TOKEN_REQUIRED:customTokenRequired, TSA_LEGACY: 'true' },
    d1Databases: {DB:'web-setup-test'}, resourcePersistencePath: directory,
  });
}
before(async () => {
  await mkdir('.wrangler', {recursive:true}); directory = await mkdtemp('.wrangler/test-web-setup-');
  modules = await workerModules();
  mf = new Miniflare(options()); db = await mf.getD1Database('DB') as unknown as D1Database;
  for (const file of ['migrations/0001_pki.sql', 'migrations/0002_web_setup.sql']) {
    const sql = (await readFile(file, 'utf8')).replace(/^--.*$/gm,''); await db.batch(sql.split(';').filter(v => v.trim()).map(v => db.prepare(v)));
  }
  pending = await generateInitialization({publicURL:'https://pki.example.com',name:'Web Test',password:backupPassword,
    rootSubject:fullSubject,issuerSubject:fullSubject.replace('CN = Pikachu Test CA RSA','CN = Pikachu Issuing CA RSA'),tsaSubject:fullSubject.replace('CN = Pikachu Test CA RSA','CN = Pikachu TSA RSA'),
    rootNotBefore:'2010-01-01T00:00:00',rootNotAfter:'2080-01-01T00:00:00Z',issuerNotBefore:'2020-01-01T00:00:00',issuerNotAfter:'2060-01-01T00:00:00'});
});
after(async () => { await mf?.dispose(); if (directory) await rm(directory,{recursive:true,force:true}); });
async function get(path: string) { return mf.dispatchFetch('https://pki.example.com'+path, {redirect:'manual'}); }
async function setup(config: unknown = pending.config, token = master, origin = 'https://pki.example.com') {
  return mf.dispatchFetch('https://pki.example.com/api/setup',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token,Origin:origin},body:JSON.stringify({publicURL:'https://pki.example.com',config})});
}
test('new deployment serves setup assets and redirects management before initialization',async () => {
  const status = await (await get('/api/setup/status')).json() as {initialized:boolean;configured:boolean};
  assert.equal(status.initialized,false); assert.equal(status.configured,true);
  const admin = await get('/admin'); assert.equal(admin.status,302); assert.equal(admin.headers.get('Location'),'/setup');
  assert.equal((await get('/health')).status,503);
  const page = await get('/setup'); assert.equal(page.status,200); assert.ok(page.headers.get('Content-Security-Policy')!.includes("script-src 'self'"));
  assert.ok((await page.text()).includes('下载加密备份'));
  const script = await get('/setup.js'); assert.equal(script.status,200); assert.ok((await script.text()).length > 10000);
});
test('browser backup contains root private key, is authenticated encrypted, and root key is absent from upload',async () => {
  assert.equal('rootPrivateKey' in pending.config,false);
  assert.equal(JSON.stringify(pending.backup).includes('PRIVATE KEY'),false);
  const backup = await decryptBackup(pending.backup,backupPassword) as {rootPrivateKey:string;config:Record<string,string>};
  assert.deepEqual(backup.config,pending.config);
  const root = new X509Certificate(pending.rootCertificate);
  const publicDER = createPublicKey(createPrivateKey(backup.rootPrivateKey)).export({format:'der',type:'spki'});
  assert.deepEqual(publicDER,root.publicKey.export({format:'der',type:'spki'}));
  assert.equal(root.verify(root.publicKey),true);
  await assert.rejects(decryptBackup(pending.backup,'wrong-password-long-enough'));
  await assert.rejects(decryptBackup({...pending.backup,ciphertext:pending.backup.ciphertext.replace(/^./,pending.backup.ciphertext[0]==='A'?'B':'A')},backupPassword));
});
test('custom CA dates survive X509 encoding including GeneralizedTime after 2050',async () => {
  assert.equal(subjectText(cert(pending.config.ROOT_CERT).subject),fullSubject);
  assert.equal(subjectText(cert(pending.config.CA_CERT).subject),fullSubject.replace('CN = Pikachu Test CA RSA','CN = Pikachu Issuing CA RSA'));
  assert.equal(subjectText(cert(pending.config.TSA_CERT).subject),fullSubject.replace('CN = Pikachu Test CA RSA','CN = Pikachu TSA RSA'));
  const root = new X509Certificate(pending.config.ROOT_CERT), issuer = new X509Certificate(pending.config.CA_CERT);
  assert.equal(new Date(root.validFrom).toISOString(),'2010-01-01T00:00:00.000Z');
  assert.equal(new Date(root.validTo).toISOString(),'2080-01-01T00:00:00.000Z');
  assert.equal(new Date(issuer.validFrom).toISOString(),'2020-01-01T00:00:00.000Z');
  assert.equal(new Date(issuer.validTo).toISOString(),'2060-01-01T00:00:00.000Z');
  assert.equal(issuer.verify(root.publicKey),true);
  const tsa = new X509Certificate(pending.config.TSA_CERT);
  assert.equal(new Date(tsa.validFrom).toISOString(),new Date(issuer.validFrom).toISOString());
  assert.equal(new Date(tsa.validTo).toISOString(),new Date(issuer.validTo).toISOString());
  assert.equal(tsa.verify(issuer.publicKey),true);
});

test('setup custom TSA dates are encoded exactly and must remain active within issuer dates',async()=>{
  const dates={rootNotBefore:'2010-01-01T00:00:00',rootNotAfter:'2080-01-01T00:00:00',issuerNotBefore:'2020-01-01T00:00:00',issuerNotAfter:'2060-01-01T00:00:00'};
  const tsaDates={tsaNotBefore:'2022-11-03T21:14:19',tsaNotAfter:'2055-11-03T21:14:19'};
  const generated=await generateInitialization({...dates,...tsaDates,publicURL:'https://pki.example.com',name:'Custom TSA Dates',password:backupPassword});
  const tsa=new X509Certificate(generated.config.TSA_CERT),issuer=new X509Certificate(generated.config.CA_CERT);
  assert.equal(new Date(tsa.validFrom).toISOString(),tsaDates.tsaNotBefore+'.000Z');
  assert.equal(new Date(tsa.validTo).toISOString(),tsaDates.tsaNotAfter+'.000Z');
  assert.equal(tsa.verify(issuer.publicKey),true);
  const backup=await decryptBackup(generated.backup,backupPassword) as {config:Record<string,string>};
  assert.equal(backup.config.TSA_CERT,generated.config.TSA_CERT);
  const now=new Date('2026-10-05T08:00:00Z');
  for(const invalid of [
    {tsaNotBefore:'2019-01-01T00:00:00'}, {tsaNotAfter:'2061-01-01T00:00:00'},
    {tsaNotBefore:'2027-01-01T00:00:00'}, {tsaNotAfter:'2025-01-01T00:00:00'},
    {tsaNotBefore:'2030-01-01T00:00:00',tsaNotAfter:'2029-01-01T00:00:00'},
    {tsaNotBefore:'2022-02-30T00:00:00'},
  ])assert.throws(()=>initializationValidity({...dates,...invalid},now));
});

test('date validation rejects normalization, inverted intervals, out-of-chain and inactive CA dates',() => {
  const now = new Date('2026-10-05T08:00:00Z');
  assert.equal(parseCertificateDate('2020-02-29T12:30').toISOString(),'2020-02-29T12:30:00.000Z');
  for (const value of ['2020-02-30T00:00:00','2026-13-01T00:00:00','2020-01-01T24:00:00','2020-01-01T00:00:00+08:00','0000-01-01T00:00:00']) assert.throws(()=>parseCertificateDate(value));
  for (const value of [
    {rootNotBefore:'2030-01-01T00:00:00'}, {rootNotAfter:'2020-01-01T00:00:00'},
    {issuerNotBefore:'2010-01-01T00:00:00'}, {issuerNotAfter:'2080-01-01T00:00:00'},
    {issuerNotBefore:'2030-01-01T00:00:00'},
  ]) assert.throws(()=>initializationValidity(value,now));
});

test('derived service validity is clipped to parent dates and invalid imported chains are refused',async () => {
  const issuer = cert(pending.config.CA_CERT), now = new Date(Math.floor(Date.now()/1000)*1000);
  issuer.notBefore = new p.Time({value:new Date(now.getTime()-5000)});
  issuer.notAfter = new p.Time({value:new Date(now.getTime()+3600000)});
  const key = await privateKey(pending.config.CA_KEY);
  const leaf = await makeCert({subject:cn('Short-lived TSA'),publicKey:issuer.subjectPublicKeyInfo,issuer,signingKey:key,profile:'tsa',days:365,now});
  assert.equal(leaf.notBefore.value.getTime(),issuer.notBefore.value.getTime());
  assert.equal(leaf.notAfter.value.getTime(),issuer.notAfter.value.getTime());
  await assert.rejects(makeCert({subject:cn('Outside parent'),publicKey:issuer.subjectPublicKeyInfo,issuer,signingKey:key,profile:'tsa',days:365,now,notBefore:new Date(now.getTime()-60000)}));
  const backup = await decryptBackup(pending.backup,backupPassword) as {rootPrivateKey:string};
  const invalid = cert(pending.config.CA_CERT); invalid.notBefore = new p.Time({value:new Date('2009-01-01T00:00:00Z')});
  await invalid.sign(await privateKey(backup.rootPrivateKey),'SHA-256');
  assert.equal((await setup({...pending.config,CA_CERT:certPEM(invalid)})).status,400);
  assert.equal(await db.prepare('SELECT id FROM pki_config').first(),null);
});

test('setup rejects unauthorized requests, cross-origin requests and invalid key/chain bundles without writes',async () => {
  assert.equal((await setup(pending.config,'bad-token')).status,401);
  assert.equal((await setup(pending.config,master,'https://attacker.example')).status,403);
  for (const config of [{...pending.config,rootPrivateKey:'must-not-upload'}, {...pending.config,TSA_KEY:pending.config.CA_KEY}, {...pending.config,CA_CERT:pending.config.ROOT_CERT}]) assert.equal((await setup(config)).status,400);
  assert.equal(await db.prepare('SELECT id FROM pki_config').first(),null);
  assert.equal(await db.prepare('SELECT serial FROM certificates').first(),null);
});
test('concurrent setup commits exactly one complete encrypted configuration with service records',async () => {
  const responses = await Promise.all([setup(),setup()]);
  assert.deepEqual(responses.map(r=>r.status).sort(),[201,409]);
  const row = await db.prepare('SELECT encrypted FROM pki_config WHERE id=1').first<{encrypted:string}>();
  assert.ok(row); assert.equal(row.encrypted.includes('PRIVATE KEY'),false); assert.equal(row.encrypted.includes(pending.config.ADMIN_TOKEN),false);
  const stored = await decryptJSON(JSON.parse(row.encrypted) as EncryptedJSON,await vaultKey(master),'signcert-pki-config-v1');
  assert.deepEqual(stored,pending.config);
  await assert.rejects(decryptJSON(JSON.parse(row.encrypted),await vaultKey('1'.repeat(64)),'signcert-pki-config-v1'));
  const records = await db.prepare('SELECT profile FROM certificates ORDER BY profile').all<{profile:string}>();
  assert.deepEqual(records.results.map(r=>r.profile),['issuer','ocsp','tsa']);
  assert.equal((await db.prepare("SELECT count(*) AS count FROM audit WHERE action='initialize'").first<{count:number}>())!.count,1);
});
test('initialized service survives Worker restart, issues certificates and keeps setup locked',async () => {
  await mf.dispose(); mf = new Miniflare(options()); db = await mf.getD1Database('DB') as unknown as D1Database;
  assert.equal((await get('/health')).status,200);
  assert.equal((await setup()).status,409);
  assert.equal((await get('/admin')).status,200);
  assert.equal(await (await get('/ca/root.pem')).text(),pending.rootCertificate);
  const keys = await rsaKeys(); const publicKey = new p.PublicKeyInfo(); await publicKey.importKey(keys.publicKey);
  const csr = new p.CertificationRequest({version:0,subject:cn('Web Issued Leaf'),subjectPublicKeyInfo:publicKey}); await csr.sign(keys.privateKey,'SHA-256');
  const response = await mf.dispatchFetch('https://pki.example.com/api/certificates',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+pending.config.ADMIN_TOKEN},body:JSON.stringify({csr:pem(csr.toSchema().toBER(false),'CERTIFICATE REQUEST'),profile:'code-signing'})});
  assert.equal(response.status,201,await response.clone().text());
  const issued = await response.json() as {certificate:string;serial:string};
  assert.equal(new X509Certificate(issued.certificate).verify(new X509Certificate(pending.config.CA_CERT).publicKey),true);
  const unauthorized = await mf.dispatchFetch('https://pki.example.com/api/certificates',{headers:{Authorization:'Bearer '+master}}); assert.equal(unauthorized.status,401);
});
test('leaf issuance preserves exact custom dates for all profiles and enforces validity bounds',async () => {
  const keys = await rsaKeys(); const publicKey = new p.PublicKeyInfo(); await publicKey.importKey(keys.publicKey);
  const csr = new p.CertificationRequest({version:0,subject:subjectFromText(fullSubject),subjectPublicKeyInfo:publicKey}); await csr.sign(keys.privateKey,'SHA-256');
  const request = pem(csr.toSchema().toBER(false),'CERTIFICATE REQUEST');
  const issue = (input:Record<string,unknown>) => mf.dispatchFetch('https://pki.example.com/api/certificates',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+pending.config.ADMIN_TOKEN},body:JSON.stringify({csr:request,profile:'code-signing',...input})});
  for (const [profile,start,end] of [['code-signing','2020-01-01T00:00:00Z','2020-04-01T00:00:00Z'],['server','2051-01-01T00:00:00','2051-04-01T00:00:00'],['client','2027-01-01T00:00:00','2027-04-01T00:00:00']]) {
    const response = await issue({profile,notBefore:start,notAfter:end,...(profile==='server'?{dnsNames:['app.example.com']}:{})});
    assert.equal(response.status,201,await response.clone().text());
    const value = await response.json() as {certificate:string;notBefore:string;notAfter:string};
    const certificate = new X509Certificate(value.certificate);
    assert.equal(subjectText(cert(value.certificate).subject),fullSubject);
    assert.ok(certificate.subjectAltName!.includes('email:testca@certs.us.kg'));
    assert.equal(new Date(certificate.validFrom).toISOString(),parseCertificateDate(start).toISOString());
    assert.equal(new Date(certificate.validTo).toISOString(),parseCertificateDate(end).toISOString());
    assert.equal(value.notBefore,new Date(certificate.validFrom).toISOString());
    assert.equal(value.notAfter,new Date(certificate.validTo).toISOString());
    assert.equal(certificate.verify(new X509Certificate(pending.config.CA_CERT).publicKey),true);
    if (profile==='server') assert.equal(certificate.checkHost('app.example.com'),'app.example.com');
  }
  for (const input of [
    {notBefore:'2020-01-01T00:00:00'},
    {notBefore:'2020-01-01T00:00:00',notAfter:'2020-04-01T00:00:00',days:90},
    {notBefore:'2020-02-30T00:00:00',notAfter:'2020-04-01T00:00:00'},
    {notBefore:'2020-04-01T00:00:00',notAfter:'2020-01-01T00:00:00'},
    {notBefore:'2020-01-01T00:00:00',notAfter:'2021-01-01T00:00:00'},
    {notBefore:'2019-01-01T00:00:00',notAfter:'2019-04-01T00:00:00'},
    {notBefore:'2060-01-01T00:00:00',notAfter:'2060-04-01T00:00:00'},
  ]) assert.equal((await issue(input)).status,400);
});

test('private CA permits configured long validity while retaining policy and issuer bounds',async () => {
  const generated = await browserCSR('Long Validity Leaf');
  const issue = (start:string,end:string) => mf.dispatchFetch('https://pki.example.com/api/certificates',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+pending.config.ADMIN_TOKEN},body:JSON.stringify({csr:generated.csr,profile:'code-signing',notBefore:start,notAfter:end})});
  try {
    await mf.setOptions(options(master,'7300'));
    const response = await issue('2021-04-03T21:11:19','2040-11-03T21:11:19');
    assert.equal(response.status,201,await response.clone().text());
    const value = await response.json() as {certificate:string};
    const certificate = new X509Certificate(value.certificate);
    assert.equal(new Date(certificate.validFrom).toISOString(),'2021-04-03T21:11:19.000Z');
    assert.equal(new Date(certificate.validTo).toISOString(),'2040-11-03T21:11:19.000Z');
    assert.equal(certificate.verify(new X509Certificate(pending.config.CA_CERT).publicKey),true);
    assert.equal((await issue('2020-01-01T00:00:00','2041-01-01T00:00:00')).status,400);
    assert.equal((await issue('2011-04-03T21:11:19','2030-11-03T21:11:19')).status,400);
    for (const invalid of ['', '0', '-1', '1.5', 'NaN', '9007199254740992']) {
      await mf.setOptions(options(master,invalid));
      const refused = await issue('2021-01-01T00:00:00','2021-02-01T00:00:00');
      assert.equal(refused.status,503);
      assert.match(await refused.text(),/MAX_VALIDITY_DAYS/);
    }
  } finally {
    await mf.setOptions(options());
    db = await mf.getD1Database('DB') as unknown as D1Database;
  }
});

test('web initialized TSA preserves custom time and OCSP signs real service status',async () => {
  const req = new p.TimeStampReq({version:1,certReq:true,messageImprint:new p.MessageImprint({hashAlgorithm:new p.AlgorithmIdentifier({algorithmId:OID.sha256}),hashedMessage:new a.OctetString({valueHex:await digest(new Uint8Array([1,2,3]).buffer)})})});
  const response = await mf.dispatchFetch('https://pki.example.com/2020-01-01T00:00:00?token='+pending.config.TSA_CUSTOM_TOKEN,{method:'POST',headers:{'Content-Type':'application/timestamp-query'},body:req.toSchema().toBER(false)});
  assert.equal(response.status,200); const parsed = new p.TimeStampResp({schema:decode(await response.arrayBuffer())}); assert.equal(parsed.status.status,0);
  const sd = new p.SignedData({schema:parsed.timeStampToken!.content}); const info = new p.TSTInfo({schema:decode(sd.encapContentInfo.eContent!.getValue())}); assert.equal(info.genTime.toISOString(),'2020-01-01T00:00:00.000Z');
  const query = new p.OCSPRequest(); await query.createForCertificate(cert(pending.config.TSA_CERT),{issuerCertificate:cert(pending.config.CA_CERT),hashAlgorithm:'SHA-256'});
  const result = await mf.dispatchFetch('https://pki.example.com/ocsp',{method:'POST',headers:{'Content-Type':'application/ocsp-request'},body:query.toSchema(true).toBER(false)});
  const ocsp = new p.OCSPResponse({schema:decode(await result.arrayBuffer())}); assert.equal(ocsp.responseStatus.valueBlock.valueDec,0);
  const basic = new p.BasicOCSPResponse({schema:decode(ocsp.responseBytes!.response.getValue())});
  assert.equal(await basic.verify({trustedCerts:[cert(pending.config.ROOT_CERT)],issuerCerts:[cert(pending.config.CA_CERT)]}),true);
});
test('online service renewal replaces keys atomically and preserves old certificate status',async () => {
  const renew = (service:string,token=pending.config.ADMIN_TOKEN) => mf.dispatchFetch('https://pki.example.com/api/services/'+service+'/renew',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:'{}'});
  assert.equal((await renew('tsa','bad-token')).status,401);
  const response = await renew('tsa'); assert.equal(response.status,201,await response.clone().text());
  const value = await response.json() as {certificate:string;serial:string};
  assert.notEqual(value.certificate,pending.config.TSA_CERT);
  assert.equal(new X509Certificate(value.certificate).verify(new X509Certificate(pending.config.CA_CERT).publicKey),true);
  assert.equal(await (await get('/ca/tsa.pem')).text(),value.certificate);
  const row = (await db.prepare('SELECT encrypted FROM pki_config WHERE id=1').first<{encrypted:string}>())!;
  const config = await decryptJSON(JSON.parse(row.encrypted),await vaultKey(master),'signcert-pki-config-v1') as Record<string,string>;
  assert.equal(config.TSA_CERT,value.certificate); assert.notEqual(config.TSA_KEY,pending.config.TSA_KEY);
  assert.equal(config.ADMIN_TOKEN,pending.config.ADMIN_TOKEN); assert.equal(config.ROOT_CERT,pending.config.ROOT_CERT);
  const publicDER = createPublicKey(createPrivateKey(config.TSA_KEY)).export({format:'der',type:'spki'});
  assert.deepEqual(publicDER,new X509Certificate(value.certificate).publicKey.export({format:'der',type:'spki'}));
  const old = await db.prepare('SELECT count(*) AS count FROM certificates WHERE profile=?').bind('tsa').first<{count:number}>(); assert.equal(old!.count,2);
  const concurrent = await Promise.all([renew('ocsp'),renew('ocsp')]);
  // Workerd may serialize the native key generation; both requests may then
  // commit successive valid renewals instead of racing on the same version.
  assert.ok(concurrent.every(r=>[201,409].includes(r.status)));
  const committed = concurrent.filter(r=>r.status===201).length; assert.ok(committed>=1);
  assert.equal((await db.prepare("SELECT count(*) AS count FROM certificates WHERE profile='ocsp'").first<{count:number}>())!.count,1+committed);
  assert.equal((await db.prepare("SELECT count(*) AS count FROM audit WHERE action='renew-service'").first<{count:number}>())!.count,1+committed);
  const current = await (await get('/ca/ocsp.pem')).text();
  const successful = await Promise.all(concurrent.filter(r=>r.status===201).map(r=>r.json() as Promise<{certificate:string}>));
  assert.ok(successful.some(value=>value.certificate===current));
  assert.equal((await get('/health')).status,200);
});

test('TSA configuration replaces the active key with custom dates and preserves historical records',async () => {
  assert.equal((await get('/admin/tsa')).status,200);
  assert.ok((await (await get('/tsa-admin.js')).text()).length>1000);
  assert.equal((await get('/api/services/tsa')).status,401);
  const headers={'Content-Type':'application/json',Authorization:'Bearer '+pending.config.ADMIN_TOKEN};
  const load=()=>mf.dispatchFetch('https://pki.example.com/api/services/tsa',{headers});
  const renew=(input:Record<string,unknown>)=>mf.dispatchFetch('https://pki.example.com/api/services/tsa/renew',{method:'POST',headers,body:JSON.stringify(input)});
  const previous=await (await load()).json() as {serial:string;notBefore:string;notAfter:string;mode:string};
  assert.equal(previous.mode,'web');
  const before=(await db.prepare('SELECT encrypted FROM pki_config WHERE id=1').first<{encrypted:string}>())!;
  for(const input of [
    {notBefore:'2020-01-01T00:00:00'},
    {notBefore:'2019-01-01T00:00:00',notAfter:'2050-01-01T00:00:00'},
    {notBefore:'2020-01-01T00:00:00',notAfter:'2061-01-01T00:00:00'},
    {notBefore:'2050-01-01T00:00:00',notAfter:'2051-01-01T00:00:00'},
    {notBefore:'2020-01-01T00:00:00',notAfter:'2021-01-01T00:00:00'},
    {notBefore:'2020-02-30T00:00:00',notAfter:'2050-01-01T00:00:00'},
    {subject:''},{subject:123},{TSA_KEY:'unexpected'},{days:7300},
  ]) assert.equal((await renew(input)).status,400);
  assert.equal((await db.prepare('SELECT encrypted FROM pki_config WHERE id=1').first<{encrypted:string}>())!.encrypted,before.encrypted);
  const response=await renew({subjectDN:fullSubject.replace('CN = Pikachu Test CA RSA','CN = Historical Timestamp Authority'),notBefore:'2020-01-01T00:00:00',notAfter:'2050-01-01T00:00:00',expectedSerial:previous.serial});
  assert.equal(response.status,201,await response.clone().text());
  const issued=await response.json() as {serial:string;certificate:string;notBefore:string;notAfter:string};
  assert.equal(issued.notBefore,'2020-01-01T00:00:00.000Z');assert.equal(issued.notAfter,'2050-01-01T00:00:00.000Z');
  assert.notEqual(issued.serial,previous.serial);
  const tsa=cert(issued.certificate);
  assert.equal(subjectText(tsa.subject),fullSubject.replace('CN = Pikachu Test CA RSA','CN = Historical Timestamp Authority'));
  assert.equal(tsa.extensions!.find(e=>e.extnID==='2.5.29.37')!.critical,true);
  assert.deepEqual(tsa.extensions!.find(e=>e.extnID==='2.5.29.37')!.parsedValue.keyPurposes,[OID.tsa]);
  const publicResult=await (await load()).text();assert.equal(publicResult.includes('PRIVATE KEY'),false);assert.equal(publicResult.includes(pending.config.ADMIN_TOKEN),false);
  assert.equal(await (await get('/ca/tsa.pem')).text(),issued.certificate);
  assert.equal((await db.prepare('SELECT status FROM certificates WHERE serial=?').bind(previous.serial).first<{status:string}>())!.status,'good');
  const after=(await db.prepare('SELECT encrypted FROM pki_config WHERE id=1').first<{encrypted:string}>())!;
  const oldConfig=await decryptJSON(JSON.parse(before.encrypted),await vaultKey(master),'signcert-pki-config-v1') as Record<string,string>;
  const newConfig=await decryptJSON(JSON.parse(after.encrypted),await vaultKey(master),'signcert-pki-config-v1') as Record<string,string>;
  assert.notEqual(oldConfig.TSA_KEY,newConfig.TSA_KEY);
  for(const key of ['ROOT_CERT','CA_CERT','CA_KEY','ADMIN_TOKEN','TSA_CUSTOM_TOKEN','OCSP_CERT','OCSP_KEY'])assert.equal(newConfig[key],oldConfig[key]);
  assert.equal((await renew({expectedSerial:previous.serial})).status,409);
  const data=new Uint8Array([5,6,7]).buffer;
  const request=new p.TimeStampReq({version:1,certReq:true,messageImprint:new p.MessageImprint({hashAlgorithm:new p.AlgorithmIdentifier({algorithmId:OID.sha256}),hashedMessage:new a.OctetString({valueHex:await digest(data)})})});
  const timestamp=await mf.dispatchFetch('https://pki.example.com/2020-04-03T21:11:19?token='+pending.config.TSA_CUSTOM_TOKEN,{method:'POST',headers:{'Content-Type':'application/timestamp-query'},body:request.toSchema().toBER(false)});
  const parsed=new p.TimeStampResp({schema:decode(await timestamp.arrayBuffer())});assert.equal(parsed.status.status,0);
  const signed=new p.SignedData({schema:parsed.timeStampToken!.content});
  assert.equal(await signed.verify({signer:0,data,checkChain:true,trustedCerts:[cert(pending.config.ROOT_CERT)]}),true);
  assert.equal(serial((signed.certificates![0] as p.Certificate).serialNumber),issued.serial);
  assert.equal((await get('/health')).status,200);
});

test('anonymous custom timestamps require explicit opt-in for both protocols and preserve management authentication',async () => {
  const data=new Uint8Array([7,8,9]).buffer;
  const request=new p.TimeStampReq({version:1,certReq:true,messageImprint:new p.MessageImprint({hashAlgorithm:new p.AlgorithmIdentifier({algorithmId:OID.sha256}),hashedMessage:new a.OctetString({valueHex:await digest(data)})})});
  const rfc=(path='/2022-11-03T21:14:19/')=>mf.dispatchFetch('https://pki.example.com'+path,{method:'POST',headers:{'Content-Type':'application/timestamp-query'},body:request.toSchema().toBER(false)});
  const payload=crypto.getRandomValues(new Uint8Array(256)).buffer;
  const spc=new a.Sequence({value:[new a.ObjectIdentifier({value:'1.3.6.1.4.1.311.3.2.1'}),new a.Sequence({value:[new a.ObjectIdentifier({value:'1.2.840.113549.1.7.1'}),new a.Constructed({idBlock:{tagClass:3,tagNumber:0},value:[new a.OctetString({valueHex:payload})]})]})]}).toBER(false);
  const legacy=()=>mf.dispatchFetch('https://pki.example.com/2022-11-03T21:14:19/',{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:Buffer.from(spc).toString('base64')});
  try {
    assert.equal((await rfc()).status,401);
    await mf.setOptions(options(master,'365','false'));
    const response=await rfc();assert.equal(response.status,200);
    const parsed=new p.TimeStampResp({schema:decode(await response.arrayBuffer())});assert.equal(parsed.status.status,0);
    const sd=new p.SignedData({schema:parsed.timeStampToken!.content});
    const info=new p.TSTInfo({schema:decode(sd.encapContentInfo.eContent!.getValue())});
    assert.equal(info.genTime.toISOString(),'2022-11-03T21:14:19.000Z');
    assert.equal(await sd.verify({signer:0,data,checkChain:true,trustedCerts:[cert(pending.config.ROOT_CERT)]}),true);
    const oldProtocol=await legacy();assert.equal(oldProtocol.status,200);
    const content=new p.ContentInfo({schema:decode(Uint8Array.from(Buffer.from(await oldProtocol.text(),'base64')).buffer)});
    assert.equal(await new p.SignedData({schema:content.content}).verify({signer:0,checkChain:true,trustedCerts:[cert(pending.config.ROOT_CERT)]}),true);
    assert.equal((await get('/api/certificates')).status,401);
    assert.equal((await get('/api/services/tsa')).status,401);
    assert.equal((await rfc('/2022-02-30T21:14:19/')).status,400);
    await mf.setOptions(options(master,'365','false','false'));assert.equal((await rfc()).status,403);
    for(const value of ['true','', 'FALSE','invalid']) {
      await mf.setOptions(options(master,'365',value));assert.equal((await rfc()).status,401);assert.equal((await legacy()).status,401);
    }
  } finally {await mf.setOptions(options());db=await mf.getD1Database('DB') as unknown as D1Database;}
});

test('browser CSR signs through Worker, CER downloads and encrypted PFX round-trip preserves leaf key and chain',async () => {
  const generated = await browserCSR('Browser PFX Test',fullSubject.replace('CN = Pikachu Test CA RSA','CN = Browser PFX Test'));
  const response = await mf.dispatchFetch('https://pki.example.com/api/certificates',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+pending.config.ADMIN_TOKEN},body:JSON.stringify({csr:generated.csr,profile:'code-signing',days:90})});
  assert.equal(response.status,201); const issued = await response.json() as {certificate:string;chain:string}; exportedCertificate=issued.certificate;
  assert.equal(subjectText(cert(issued.certificate).subject),fullSubject.replace('CN = Pikachu Test CA RSA','CN = Browser PFX Test'));
  exportedPFX = await createPFX(issued.certificate,issued.chain,generated.keys.privateKey,exportPassword);
  const password = new TextEncoder().encode(exportPassword).buffer;
  const bundle = new p.PFX({schema:decode(exportedPFX)}); await bundle.parseInternalValues({password,checkIntegrity:true});
  assert.equal(bundle.macData!.mac.digestAlgorithm.algorithmId,OID.sha256);
  const authSafe=bundle.parsedValue!.authenticatedSafe!;
  await authSafe.parseInternalValues({safeContents:[{password},{}]});
  const contents = new p.SafeContents({safeBags:[...authSafe.parsedValue.safeContents[1].value.safeBags,...authSafe.parsedValue.safeContents[0].value.safeBags]});
  assert.equal(contents.safeBags.length,4);
  const keyBag = contents.safeBags[0].bagValue as p.PKCS8ShroudedKeyBag;
  assert.ok(keyBag instanceof p.PKCS8ShroudedKeyBag);
  const encrypted = new p.EncryptedData({encryptedContentInfo:new p.EncryptedContentInfo({contentEncryptionAlgorithm:keyBag.encryptionAlgorithm,encryptedContent:keyBag.encryptedData})});
  const decrypted = await encrypted.decrypt({password});
  assert.deepEqual(new Uint8Array(decrypted),new Uint8Array(await crypto.subtle.exportKey('pkcs8',generated.keys.privateKey)));
  assert.equal(new X509Certificate(((contents.safeBags[1].bagValue as p.CertBag).certValue as a.OctetString).valueBlock.valueHexView).fingerprint256,new X509Certificate(issued.certificate).fingerprint256);
  assert.deepEqual(contents.safeBags[0].bagAttributes!.map(a=>a.toSchema().toBER(false)),contents.safeBags[1].bagAttributes!.map(a=>a.toSchema().toBER(false)));
  const wrong = new p.PFX({schema:decode(exportedPFX)});
  await assert.rejects(wrong.parseInternalValues({password:new TextEncoder().encode('wrong-pfx-password').buffer,checkIntegrity:true}));
  const tampered = new p.PFX({schema:decode(exportedPFX)});
  const raw = (tampered.authSafe.content as a.OctetString).valueBlock.valueHexView; raw[raw.length-1]^=1;
  await assert.rejects(tampered.parseInternalValues({password,checkIntegrity:true}));
  const different = await browserCSR('Other Key');
  await assert.rejects(createPFX(issued.certificate,issued.chain,different.keys.privateKey,exportPassword),/不匹配/);
  for (const name of ['root','issuer','tsa','ocsp']) {
    const cer = await get('/ca/'+name+'.cer'); assert.equal(cer.status,200);assert.ok(cer.headers.get('Content-Disposition')!.includes(name+'.cer'));
    const original = await (await get('/ca/'+name+'.pem')).text();
    assert.equal(new X509Certificate(new Uint8Array(await cer.arrayBuffer())).fingerprint256,new X509Certificate(original).fingerprint256);
  }
});

test('OpenSSL via cryptography reads PFX and verifies key, chain and password',{skip:!process.env.SIGNCERT_TEST_PYTHON},() => {
  const script = `import sys,json,base64
from cryptography.hazmat.primitives.serialization import pkcs12,Encoding,PublicFormat
d=json.load(sys.stdin)
raw=base64.b64decode(d['pfx'])
key,cert,chain=pkcs12.load_key_and_certificates(raw,d['password'].encode('utf-8'))
wrong=False
try: pkcs12.load_key_and_certificates(raw,b'wrong-password')
except ValueError: wrong=True
print(json.dumps({'chain':len(chain),'matches':key.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)==cert.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo),'wrongRejected':wrong,'cer':base64.b64encode(cert.public_bytes(Encoding.DER)).decode()}))`;
  const result=spawnSync(process.env.SIGNCERT_TEST_PYTHON!,['-X','utf8','-c',script],{input:JSON.stringify({pfx:Buffer.from(exportedPFX).toString('base64'),password:exportPassword}),encoding:'utf8',timeout:30000,maxBuffer:1024*1024});
  assert.equal(result.status,0,result.stderr||result.error?.message||'PFX import failed');
  const value=JSON.parse(result.stdout);assert.equal(value.chain,2);assert.equal(value.matches,true);assert.equal(value.wrongRejected,true);
  assert.equal(new X509Certificate(Buffer.from(value.cer,'base64')).fingerprint256,new X509Certificate(exportedCertificate).fingerprint256);
});

test('Windows imports PFX with private key and three certificates using ephemeral key storage',{skip:process.platform!=='win32'},() => {
  const script = `$ErrorActionPreference='Stop'
    [Console]::InputEncoding=[System.Text.UTF8Encoding]::new($false)
    $data=[Console]::In.ReadToEnd() | ConvertFrom-Json
    $certOnly=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($data.cer))
    $bundle=[System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    try { $bundle.Import([Convert]::FromBase64String($data.pfx),$data.password,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet) } catch { throw $_.Exception.InnerException.ToString() }
    $leaf=@($bundle | Where-Object HasPrivateKey)[0]
    $key=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($leaf)
    $public=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($leaf)
    $challenge=[byte[]](1,2,3,4)
    $signature=$key.SignData($challenge,[System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $verified=$public.VerifyData($challenge,$signature,[System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $wrongRejected=$false
    try { $bad=[System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new(); $bad.Import([Convert]::FromBase64String($data.pfx),'wrong-password',[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet) } catch { $wrongRejected=$true }
    @{count=$bundle.Count;privateKeys=@($bundle | Where-Object HasPrivateKey).Count;verified=$verified;wrongRejected=$wrongRejected;cer=[Convert]::ToBase64String($leaf.RawData)} | ConvertTo-Json -Compress
    $key.Dispose();$public.Dispose();$certOnly.Dispose();foreach($certificate in $bundle){$certificate.Dispose()}`;
  const options={input:JSON.stringify({pfx:Buffer.from(exportedPFX).toString('base64'),password:exportPassword,cer:Buffer.from(new X509Certificate(exportedCertificate).raw).toString('base64')}),encoding:'utf8' as const,timeout:30000,maxBuffer:1024*1024};
  let result = spawnSync('pwsh',['-NoProfile','-NonInteractive','-Command',script],options);
  if (result.error && 'code' in result.error && result.error.code==='ENOENT') result=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',script],options);
  assert.equal(result.status,0,result.stderr||result.error?.message||'PFX import failed');
  const value = JSON.parse(result.stdout); assert.equal(value.count,3);assert.equal(value.privateKeys,1);assert.equal(value.verified,true);assert.equal(value.wrongRejected,true);
  assert.equal(new X509Certificate(Buffer.from(value.cer,'base64')).fingerprint256,new X509Certificate(exportedCertificate).fingerprint256);
});

test('wrong deployment master key cannot read encrypted PKI and cannot reset it',async () => {
  await mf.dispose(); mf = new Miniflare(options('1'.repeat(64)));
  assert.equal((await get('/health')).status,503);
  const status = await (await get('/api/setup/status')).json() as {initialized:boolean}; assert.equal(status.initialized,true);
  assert.equal((await setup(pending.config,'1'.repeat(64))).status,409);
});
