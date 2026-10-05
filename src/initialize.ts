import { cn, rsaKeys, makeCert, p, certPEM, pem, hex } from './pki';
import { encryptBackup, type Backup } from './encryption';

export const CONFIG_FIELDS = ['ROOT_CERT', 'CA_CERT', 'CA_KEY', 'TSA_CERT', 'TSA_KEY', 'OCSP_CERT', 'OCSP_KEY', 'ADMIN_TOKEN', 'TSA_CUSTOM_TOKEN'] as const;
export type StoredConfig = Record<typeof CONFIG_FIELDS[number], string>;
export interface Initialization {
  publicURL: string; name: string; password: string;
  rootNotBefore?: string; rootNotAfter?: string;
  issuerNotBefore?: string; issuerNotAfter?: string;
  onProgress?: (message: string) => void;
}
export interface InitializationResult { config: StoredConfig; backup: Backup; rootCertificate: string; chain: string; }

export function parseCertificateDate(value: string): Date {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?Z?$/.test(value)) throw new Error('证书日期需要 YYYY-MM-DDTHH:mm:ss 格式（UTC）');
  const text = value.replace(/Z$/,'');
  const canonical = text.length === 16 ? text + ':00' : text;
  const date = new Date(canonical + 'Z');
  if (!Number.isFinite(date.getTime()) || date.getUTCFullYear() < 1 || date.toISOString() !== canonical + '.000Z') throw new Error('证书日期无效，请检查月份、日期与时间');
  return date;
}
export function initializationValidity(opts: Pick<Initialization,'rootNotBefore'|'rootNotAfter'|'issuerNotBefore'|'issuerNotAfter'>, now = new Date()) {
  const date = (value: string | undefined, fallback: number) => value ? parseCertificateDate(value) : new Date(Math.floor(fallback / 1000) * 1000);
  const rootStart = date(opts.rootNotBefore,now.getTime()-60000), rootEnd = date(opts.rootNotAfter,now.getTime()+3650*86400000);
  const issuerStart = date(opts.issuerNotBefore,Math.max(now.getTime()-60000,rootStart.getTime()));
  const issuerEnd = date(opts.issuerNotAfter,Math.min(now.getTime()+1825*86400000,rootEnd.getTime()));
  if (rootStart >= rootEnd || issuerStart >= issuerEnd) throw new Error('生效时间必须早于到期时间');
  if (issuerStart < rootStart || issuerEnd > rootEnd) throw new Error('签发 CA 的有效期必须位于根证书有效期内');
  if (rootStart > now || issuerStart > now || rootEnd <= now || issuerEnd <= now) throw new Error('启用服务要求根证书与签发 CA 的有效期均覆盖当前 UTC 时间');
  return {rootStart,rootEnd,issuerStart,issuerEnd};
}

export function publicOrigin(value: string): string {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.origin !== value) throw new Error('PUBLIC_URL must be an HTTPS origin without a trailing slash');
  return url.origin;
}
// Runs entirely in the browser: the root private key never appears in config.
export async function generateInitialization(opts: Initialization): Promise<InitializationResult> {
  const publicURL = publicOrigin(opts.publicURL);
  if (opts.password.length < 16 || opts.password.length > 1024) throw new Error('备份密码需要 16–1024 个字符');
  const label = opts.name.trim(); cn(label);
  if (label.length > 90) throw new Error('名称不能超过 90 个字符');
  const validity = initializationValidity(opts);
  const pub = async (key: CryptoKey) => { const value = new p.PublicKeyInfo(); await value.importKey(key); return value; };
  opts.onProgress?.('正在生成根 CA…');
  const rootKeys = await rsaKeys();
  const root = await makeCert({ subject: cn(`${label} Root CA`), publicKey: await pub(rootKeys.publicKey), signingKey: rootKeys.privateKey, profile: 'root', days: 3650, notBefore:validity.rootStart,notAfter:validity.rootEnd });
  opts.onProgress?.('正在生成签发 CA…');
  const caKeys = await rsaKeys();
  const ca = await makeCert({ subject: cn(`${label} Issuing CA`), publicKey: await pub(caKeys.publicKey), issuer: root, signingKey: rootKeys.privateKey, profile: 'issuer', days: 1825,notBefore:validity.issuerStart,notAfter:validity.issuerEnd });
  const config = {
    ROOT_CERT: certPEM(root), CA_CERT: certPEM(ca), CA_KEY: pem(await crypto.subtle.exportKey('pkcs8', caKeys.privateKey), 'PRIVATE KEY'),
    ADMIN_TOKEN: hex(crypto.getRandomValues(new Uint8Array(32))), TSA_CUSTOM_TOKEN: hex(crypto.getRandomValues(new Uint8Array(32))),
  } as StoredConfig;
  for (const service of ['tsa', 'ocsp'] as const) {
    opts.onProgress?.(`正在生成 ${service.toUpperCase()}…`);
    const keys = await rsaKeys();
    const certificate = await makeCert({ subject: cn(`${label} ${service === 'tsa' ? 'Timestamp Authority' : 'OCSP Responder'}`), publicKey: await pub(keys.publicKey), issuer: ca, signingKey: caKeys.privateKey, profile: service, days: 365, publicURL });
    config[service === 'tsa' ? 'TSA_CERT' : 'OCSP_CERT'] = certPEM(certificate);
    config[service === 'tsa' ? 'TSA_KEY' : 'OCSP_KEY'] = pem(await crypto.subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY');
  }
  opts.onProgress?.('正在加密完整备份…');
  const backup = await encryptBackup({ version: 1, publicURL, createdAt: new Date().toISOString(), rootPrivateKey: pem(await crypto.subtle.exportKey('pkcs8', rootKeys.privateKey), 'PRIVATE KEY'), config }, opts.password);
  return { config, backup, rootCertificate: config.ROOT_CERT, chain: config.CA_CERT + config.ROOT_CERT };
}
