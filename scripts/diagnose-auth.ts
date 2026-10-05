import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { decryptJSON, vaultKey } from '../src/encryption';
import { validateConfig } from '../src/storage';

// Credentials arrive on stdin from Read-Host -AsSecureString, never argv or files.
async function main(): Promise<void> {
  let text = '';
  for await (const chunk of process.stdin) {
    text += chunk.toString();
    if (text.length > 4096) throw new Error('输入过长');
  }
  const input = JSON.parse(text) as {master:string;token:string};
  if (typeof input.master !== 'string' || typeof input.token !== 'string') throw new Error('请通过 diagnose-auth.ps1 运行');
  const key = await vaultKey(input.master.trim());
  const wrangler = fileURLToPath(new URL('../node_modules/wrangler/bin/wrangler.js',import.meta.url));
  const result = spawnSync(process.execPath,[wrangler,'d1','execute','signcert','--remote','--command','SELECT encrypted,created_at FROM pki_config WHERE id=1','--json'],{encoding:'utf8',maxBuffer:1024*1024,stdio:['ignore','pipe','pipe']});
  // Never print subprocess output: it contains the encrypted key bundle.
  if (result.error || result.status !== 0) throw new Error('无法读取远程 D1；请检查 Wrangler 登录、网络和 wrangler.toml');
  let row: {encrypted:string;created_at:string} | undefined;
  try { row = (JSON.parse(result.stdout) as Array<{results:Array<{encrypted:string;created_at:string}>}>)[0]?.results?.[0]; }
  catch { throw new Error('Wrangler 返回格式无法解析'); }
  if (!row) throw new Error('当前绑定的 D1 尚未初始化');
  let config;
  try { config = validateConfig(await decryptJSON(JSON.parse(row.encrypted),key,'signcert-pki-config-v1')); }
  catch { throw new Error('无法解密配置：输入的主密钥与这份 D1 配置不匹配，或配置已损坏。不要修改线上主密钥'); }
  console.log('远程 D1 初始化时间：'+row.created_at);
  if (input.token === config.ADMIN_TOKEN) console.log('结果：管理令牌完全匹配。若网页仍返回 401，应排查实际请求、域名路由和部署版本。');
  else if (input.token.trim() === config.ADMIN_TOKEN) console.log('结果：管理令牌包含首尾空白；删除空白后重新输入。');
  else if (input.token.trim() === input.master.trim()) console.log('结果：输入的是初始化主密钥，不是管理令牌。');
  else if (input.token.trim() === config.TSA_CUSTOM_TOKEN) console.log('结果：输入的是自定义时间戳令牌，不是管理令牌。');
  else console.log('结果：令牌与当前 D1 中的管理令牌不匹配。请在 /setup 解密此次初始化保存的备份，重新复制管理令牌。');
}
try { await main(); }
catch (error) { console.error(error instanceof Error ? error.message : '诊断失败'); process.exitCode=1; }
