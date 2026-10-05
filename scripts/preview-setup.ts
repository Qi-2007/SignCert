// Isolated local preview. No production secrets or remote D1 are used.
import { readFile } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { workerModules } from '../test/worker-modules';
import { generateInitialization } from '../src/initialize';

const mf = new Miniflare(convertV4MiniflareOptions({host:'127.0.0.1',port:8799,modules:await workerModules(),compatibilityDate:'2026-10-01',compatibilityFlags:['nodejs_compat'],bindings:{PKI_MASTER_KEY:'d'.repeat(64),PUBLIC_URL:'https://pki.example.com',TSA_POLICY_OID:'1.3.6.1.4.1.55555.1.1',MAX_VALIDITY_DAYS:'365',TSA_FAKE:'true',TSA_LEGACY:'true'},d1Databases:{DB:'setup-preview'}}));
const db = await mf.getD1Database('DB');
for (const file of ['migrations/0001_pki.sql','migrations/0002_web_setup.sql']) {
  const sql = (await readFile(file,'utf8')).replace(/^--.*$/gm,''); await db.batch(sql.split(';').filter(v=>v.trim()).map(v=>db.prepare(v)));
}
if (process.argv.includes('--initialized')) {
  const generated=await generateInitialization({publicURL:'https://pki.example.com',name:'Local Preview',password:'local-preview-backup-password',rootNotBefore:'2000-01-01T00:00:00',rootNotAfter:'2100-01-01T00:00:00',issuerNotBefore:'2000-01-01T00:00:00',issuerNotAfter:'2100-01-01T00:00:00'});
  generated.config.ADMIN_TOKEN='a'.repeat(64);
  const response=await mf.dispatchFetch('https://pki.example.com/api/setup',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+'d'.repeat(64)},body:JSON.stringify({publicURL:'https://pki.example.com',config:generated.config})});
  if(!response.ok)throw new Error(await response.text());
  console.log('Ephemeral initialized preview at http://127.0.0.1:8799/admin/tsa. Test-only admin: the letter a repeated 64 times.');
} else console.log('Ephemeral preview at http://127.0.0.1:8799/setup. Test-only master: the letter d repeated 64 times.');
for (const signal of ['SIGINT','SIGTERM'] as const) process.on(signal,()=>{void mf.dispose().then(()=>process.exit(0));});
