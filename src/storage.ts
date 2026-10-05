import { context, cert, insertCertificate, audit, assertServiceActive, rsaKeys, p, makeCert, cn, certPEM, pem, serial, commonName, type Env } from './pki';
import { CONFIG_FIELDS, type StoredConfig, publicOrigin, parseCertificateDate } from './initialize';
import { decryptJSON, encryptJSON, vaultKey, type EncryptedJSON } from './encryption';

export const legacyConfigured = (env: Env): boolean => Boolean(env.ROOT_CERT || env.CA_CERT || env.CA_KEY);
const vaultAAD = 'signcert-pki-config-v1';
const resolved = new WeakMap<object, {encrypted:string;result:Promise<Env>}>();
export class AlreadyInitialized extends Error {}
export function validateConfig(input: unknown): StoredConfig {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Invalid PKI configuration');
  const value = input as Record<string, unknown>;
  if (Object.keys(value).length !== CONFIG_FIELDS.length || Object.keys(value).some(key => !CONFIG_FIELDS.includes(key as typeof CONFIG_FIELDS[number]))) throw new Error('Unexpected configuration fields; root private key must remain offline');
  for (const field of CONFIG_FIELDS) if (typeof value[field] !== 'string' || !value[field] || (value[field] as string).length > 12000) throw new Error(`Missing or invalid ${field}`);
  for (const field of ['ADMIN_TOKEN', 'TSA_CUSTOM_TOKEN']) if (!/^[0-9a-f]{64}$/.test(value[field] as string)) throw new Error(`Invalid ${field}`);
  return value as StoredConfig;
}
export async function setupStatus(env: Env): Promise<{ initialized: boolean; mode: 'web' | 'secrets' | 'uninitialized'; configured: boolean; publicURL: string }> {
  const legacy = legacyConfigured(env);
  const row = legacy ? null : await env.DB.prepare('SELECT id FROM pki_config WHERE id=1').first();
  return { initialized: legacy || Boolean(row), mode: legacy ? 'secrets' : row ? 'web' : 'uninitialized', configured: /^[0-9a-fA-F]{64}$/.test(env.PKI_MASTER_KEY ?? ''), publicURL: env.PUBLIC_URL };
}
export async function runtimeEnv(env: Env): Promise<Env | null> {
  if (legacyConfigured(env)) return env;
  const row = await env.DB.prepare('SELECT encrypted FROM pki_config WHERE id=1').first<{encrypted:string}>();
  if (!row) return null;
  const cached = resolved.get(env); if (cached?.encrypted === row.encrypted) return cached.result;
  const result = (async () => {
    const config = validateConfig(await decryptJSON(JSON.parse(row.encrypted) as EncryptedJSON, await vaultKey(env.PKI_MASTER_KEY ?? ''), vaultAAD));
    return { ...env, ...config };
  })();
  resolved.set(env, {encrypted:row.encrypted,result}); result.catch(() => resolved.delete(env));
  return result;
}
export async function initialize(env: Env, input: unknown): Promise<void> {
  const status = await setupStatus(env);
  if (status.initialized) throw new AlreadyInitialized('PKI already initialized');
  // Also protect existing records if a legacy installation dropped its secrets.
  if (await env.DB.prepare('SELECT serial FROM certificates LIMIT 1').first()) throw new AlreadyInitialized('Existing certificate records prevent initialization');
  publicOrigin(env.PUBLIC_URL);
  const config = validateConfig(input);
  const effective = { ...env, ...config };
  const ctx = await context(effective); // Checks chain, purposes, CA constraints, key matches and validity.
  for (const service of [ctx.tsa, ctx.ocsp]) if (Date.now() < service.notBefore.value.getTime() || Date.now() >= service.notAfter.value.getTime()) throw new Error('Service certificate outside validity');
  const encrypted = await encryptJSON(config, await vaultKey(env.PKI_MASTER_KEY ?? ''), vaultAAD);
  try {
    await env.DB.batch([
      env.DB.prepare('INSERT INTO pki_config (id,encrypted,created_at) VALUES (1,?,?)').bind(JSON.stringify(encrypted), new Date().toISOString()),
      insertCertificate(env.DB, cert(config.CA_CERT), 'issuer'), insertCertificate(env.DB, cert(config.TSA_CERT), 'tsa'), insertCertificate(env.DB, cert(config.OCSP_CERT), 'ocsp'),
      audit(env.DB, 'initialize', null, JSON.stringify({ publicURL: env.PUBLIC_URL, mode: 'web' })),
    ]);
  } catch (error) {
    if (await env.DB.prepare('SELECT id FROM pki_config WHERE id=1').first()) throw new AlreadyInitialized('PKI already initialized');
    throw error;
  }
  resolved.delete(env);
}

export interface ServiceOptions {subject?:string;notBefore?:string;notAfter?:string;expectedSerial?:string}
export class InvalidServiceConfiguration extends Error {}
export async function renewService(env: Env, service: 'tsa' | 'ocsp', options:ServiceOptions = {}): Promise<{serial:string;certificate:string;chain:string;notBefore:string;notAfter:string}> {
  if (legacyConfigured(env)) throw new AlreadyInitialized('Secrets mode uses the offline renew-service script');
  const row = await env.DB.prepare('SELECT encrypted FROM pki_config WHERE id=1').first<{encrypted:string}>();
  if (!row) throw new AlreadyInitialized('PKI not initialized');
  const key = await vaultKey(env.PKI_MASTER_KEY ?? '');
  const config = validateConfig(await decryptJSON(JSON.parse(row.encrypted),key,vaultAAD));
  const effective = {...env,...config}; const ctx = await context(effective); await assertServiceActive(effective,ctx.ca);
  const previous = service === 'tsa' ? ctx.tsa : ctx.ocsp;
  if (options.expectedSerial !== undefined && options.expectedSerial !== serial(previous.serialNumber)) throw new AlreadyInitialized('当前服务证书已改变，请重新加载后再签发');
  let notBefore:Date|undefined, notAfter:Date|undefined;
  const subject = options.subject ?? commonName(previous.subject);
  try {
    if (!subject.trim() || subject !== subject.trim() || subject.length > 128) throw new Error('证书名称需要 1–128 个字符，且不能包含首尾空格');
    cn(subject);
    if (options.notBefore !== undefined || options.notAfter !== undefined) {
      if (typeof options.notBefore !== 'string' || typeof options.notAfter !== 'string') throw new Error('请同时填写生效与到期时间');
      notBefore = parseCertificateDate(options.notBefore); notAfter = parseCertificateDate(options.notAfter);
      if (notBefore >= notAfter) throw new Error('生效时间必须早于到期时间');
      if (notBefore < ctx.ca.notBefore.value || notAfter > ctx.ca.notAfter.value) throw new Error('服务证书有效期必须位于签发 CA 有效期内');
      const now = new Date();
      if (notBefore > now || notAfter <= now) throw new Error('启用服务要求证书有效期覆盖当前 UTC 时间');
    }
  } catch (error) { throw new InvalidServiceConfiguration(error instanceof Error ? error.message : '服务证书配置无效'); }
  const keys = await rsaKeys(); const publicKey = new p.PublicKeyInfo(); await publicKey.importKey(keys.publicKey);
  const certificate = await makeCert({subject:cn(subject),publicKey,issuer:ctx.ca,signingKey:ctx.caKey,profile:service,days:365,publicURL:env.PUBLIC_URL,notBefore,notAfter});
  config[service === 'tsa' ? 'TSA_CERT' : 'OCSP_CERT'] = certPEM(certificate);
  config[service === 'tsa' ? 'TSA_KEY' : 'OCSP_KEY'] = pem(await crypto.subtle.exportKey('pkcs8',keys.privateKey),'PRIVATE KEY');
  const next = JSON.stringify(await encryptJSON(config,key,vaultAAD)); const at = new Date().toISOString(); const id = serial(certificate.serialNumber);
  // Compare-and-swap and guarded inserts avoid lost updates from concurrent renewal requests.
  const result = await env.DB.batch([
    env.DB.prepare('UPDATE pki_config SET encrypted=? WHERE id=1 AND encrypted=?').bind(next,row.encrypted),
    env.DB.prepare('INSERT INTO certificates (serial,pem,subject,profile,not_before,not_after,created_at) SELECT ?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM pki_config WHERE id=1 AND encrypted=?)').bind(id,certPEM(certificate),commonName(certificate.subject),service,certificate.notBefore.value.toISOString(),certificate.notAfter.value.toISOString(),at,next),
    env.DB.prepare("INSERT INTO audit (action,serial,at,detail) SELECT 'renew-service',?,?,? WHERE EXISTS (SELECT 1 FROM pki_config WHERE id=1 AND encrypted=?)").bind(id,at,JSON.stringify({service,previousSerial:serial(previous.serialNumber),notBefore:certificate.notBefore.value.toISOString(),notAfter:certificate.notAfter.value.toISOString()}),next),
  ]);
  if (result[0].meta.changes !== 1) throw new AlreadyInitialized('Service configuration changed; reload and retry renewal');
  resolved.delete(env);
  return {serial:id,certificate:certPEM(certificate),chain:config.CA_CERT+config.ROOT_CERT,notBefore:certificate.notBefore.value.toISOString(),notAfter:certificate.notAfter.value.toISOString()};
}
