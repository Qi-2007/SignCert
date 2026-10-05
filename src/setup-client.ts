import { generateInitialization, initializationValidity, CONFIG_FIELDS, type InitializationResult, type StoredConfig } from './initialize';
import { decryptBackup, type Backup } from './encryption';
import { cert } from './pki';

const el = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const input = (id: string) => el<HTMLInputElement>(id);
let pending: InitializationResult | undefined;
let rootPrivateKey: string | undefined;
let initialized = false, busy = false, downloaded = false;
const defaultValidity = initializationValidity({});
for (const [id,date] of [['root-start',defaultValidity.rootStart],['root-end',defaultValidity.rootEnd],['issuer-start',defaultValidity.issuerStart],['issuer-end',defaultValidity.issuerEnd]] as const) input(id).value = date.toISOString().slice(0,19);

function download(value: string, name: string, type = 'application/json'): void {
  const url = URL.createObjectURL(new Blob([value], { type }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = name;
  document.body.appendChild(anchor); anchor.click(); anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}
function errorMessage(error: unknown): string { return error instanceof Error ? error.message : '操作失败'; }
function showValidity(config: StoredConfig): void {
  const root = cert(config.ROOT_CERT), issuer = cert(config.CA_CERT);
  el('validity-preview').textContent = '根证书：'+root.notBefore.value.toISOString()+' → '+root.notAfter.value.toISOString()+'\n签发 CA：'+issuer.notBefore.value.toISOString()+' → '+issuer.notAfter.value.toISOString();
}
function updateCommit(): void { el<HTMLButtonElement>('commit').disabled = initialized || busy || !pending || !downloaded || !input('saved').checked; }
function credentials(config: StoredConfig): void {
  el('credentials-title').textContent = initialized ? '访问令牌' : '备份中的访问令牌';
  el<HTMLTextAreaElement>('admin-token').value = config.ADMIN_TOKEN;
  el<HTMLTextAreaElement>('tsa-token').value = config.TSA_CUSTOM_TOKEN;
  el('complete').hidden = false;
}
async function checkStatus(): Promise<void> {
  try {
    const response = await fetch('/api/setup/status', { cache: 'no-store', credentials: 'omit' });
    const status = await response.json() as {error?:string;initialized:boolean;publicURL:string;configured:boolean};
    if (!response.ok) throw new Error(status.error ?? '检查失败，请先执行 D1 数据库迁移');
    initialized = status.initialized;
    input('url').value = status.publicURL;
    el('restore').hidden = false;
    if (initialized) {
      el('status').textContent = '此系统已初始化，不能覆盖。可进入 /admin 管理，或在下方解密自己的离线备份。';
      el('create').hidden = true;
    } else if (!status.configured) {
      el('status').textContent = '请先在 Cloudflare 的 Worker Secrets 设置 PKI_MASTER_KEY（64 位十六进制随机密钥），再刷新页面。';
    } else {
      el('status').textContent = '系统尚未初始化。先生成并保存备份，再启用服务。';
      el('create').hidden = false;
    }
    if (!crypto.subtle) { el('create').hidden = true; throw new Error('此浏览器不支持安全密钥生成，请使用 HTTPS 或 localhost 上的现代浏览器'); }
  } catch (error) { el('status').textContent = errorMessage(error); }
  updateCommit();
}
el<HTMLFormElement>('generate').onsubmit = async event => {
  event.preventDefault(); if (busy || initialized) return;
  if (!/^[0-9a-fA-F]{64}$/.test(input('master').value)) { el('status').textContent = '主密钥应为 64 位十六进制，与 Cloudflare Secret 完全一致'; return; }
  if (input('password').value !== input('password-confirm').value) { el('status').textContent = '两次备份密码不一致'; return; }
  busy = true; el<HTMLButtonElement>('generate-button').disabled = true; updateCommit();
  try {
    const result = await generateInitialization({ publicURL: input('url').value, name: input('name').value, password: input('password').value,
      rootNotBefore:input('root-start').value,rootNotAfter:input('root-end').value,issuerNotBefore:input('issuer-start').value,issuerNotAfter:input('issuer-end').value,
      onProgress: message => { el('status').textContent = message; } });
    pending = result; rootPrivateKey = undefined; downloaded = false; input('saved').checked = false;
    showValidity(result.config);
    el('complete').hidden = true;
    el('download-private-root').hidden = true; el('backup').hidden = false;
    input('password').value = ''; input('password-confirm').value = '';
    el('status').textContent = '证书已生成，尚未上传。请先下载并保存加密备份。';
  } catch (error) { el('status').textContent = errorMessage(error); }
  finally { busy = false; el<HTMLButtonElement>('generate-button').disabled = false; updateCommit(); }
};
el('download-backup').onclick = () => { if (!pending) return; download(JSON.stringify(pending.backup, null, 2), 'signcert-backup.json'); downloaded = true; updateCommit(); };
el('download-root').onclick = () => { if (pending) download(pending.rootCertificate, 'signcert-root.pem', 'application/x-pem-file'); };
el('download-chain').onclick = () => { if (pending) download(pending.chain, 'signcert-chain.pem', 'application/x-pem-file'); };
input('saved').onchange = updateCommit;
el('commit').onclick = async () => {
  if (!pending || busy || initialized || !downloaded || !input('saved').checked) return;
  busy = true; updateCommit(); el('commit-status').textContent = '正在校验并保存配置…';
  try {
    const response = await fetch('/api/setup', { method: 'POST', credentials: 'omit', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + input('master').value }, body: JSON.stringify({ publicURL: input('url').value, config: pending.config }) });
    const result = await response.json() as {error?:string;initialized?:boolean};
    if (!response.ok) throw new Error(result.error ?? '初始化失败');
    initialized = true; credentials(pending.config); el('create').hidden = true;
    input('master').value = ''; el('commit-status').textContent = '已完成。根私钥保留在你的离线备份中。';
    el('status').textContent = '证书系统已启用。';
  } catch (error) {
    el('commit-status').textContent = errorMessage(error) + '。已下载的备份仍可使用；若响应中断，请检查系统状态后再操作。';
    // A committed transaction may succeed even if its response was lost.
    await checkStatus();
  } finally { busy = false; updateCommit(); }
};
el<HTMLFormElement>('restore-form').onsubmit = async event => {
  event.preventDefault(); if (busy) return; busy = true; updateCommit();
  try {
    const file = input('backup-file').files?.[0];
    if (!file || file.size > 200000) throw new Error('请选择有效备份文件（最多 200 KB）');
    const backup = JSON.parse(await file.text()) as Backup;
    const value = await decryptBackup(backup, input('restore-password').value) as {version:number;publicURL:string;rootPrivateKey:string;config:StoredConfig};
    if (value.version !== 1 || typeof value.rootPrivateKey !== 'string' || !value.rootPrivateKey.startsWith('-----BEGIN PRIVATE KEY-----') || !value.config || CONFIG_FIELDS.some(field => typeof value.config[field] !== 'string')) throw new Error('备份内容格式无效');
    rootPrivateKey = value.rootPrivateKey; el('download-private-root').hidden = false;
    credentials(value.config); input('restore-password').value = '';
    if (!initialized && value.publicURL === input('url').value) {
      pending = { config: value.config, backup, rootCertificate: value.config.ROOT_CERT, chain: value.config.CA_CERT + value.config.ROOT_CERT };
      showValidity(value.config);
      downloaded = true; input('saved').checked = false; el('backup').hidden = false;
      el('restore-status').textContent = '已解密。确认保存备份并输入部署主密钥后，可初始化当前空系统。';
      // A restored bundle is already saved; no password re-entry or key regeneration is needed.
      el('create').hidden = false;
      input('name').value = '恢复已有证书';
    } else el('restore-status').textContent = '备份已在本浏览器解密。可查看令牌并提取根私钥；当前系统未被修改。';
  } catch { el('restore-status').textContent = '无法解密：请检查备份文件和密码。'; }
  finally { busy = false; updateCommit(); }
};
el('download-private-root').onclick = () => { if (rootPrivateKey) download(rootPrivateKey, 'signcert-root-private.key', 'application/x-pem-file'); };
void checkStatus();
