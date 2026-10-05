import { browserCSR, createPFX, validatePFXPassword } from './client-certificate';
import { unpem } from './pki';
import {bindSubjectEditor} from './subject-ui';

const el = <T = HTMLElement>(id:string) => document.getElementById(id) as T;
const input = (id:string) => el<HTMLInputElement>(id);
const select = (id:string) => el<HTMLSelectElement>(id);
const button = (id:string) => el<HTMLButtonElement>(id);
interface CertificateRow {serial:string;pem:string;subject:string;profile:string;status:string;not_after:string}
interface Issued {serial:string;certificate:string;chain:string;notBefore:string;notAfter:string}
let offset=0, busy=false;
let current: {issued:Issued;key?:CryptoKey;pfx?:ArrayBuffer;downloaded:boolean} | undefined;
function download(data:string|ArrayBuffer,name:string,type:string):void {
  const url=URL.createObjectURL(new Blob([data],{type}));
  const link=document.createElement('a'); link.href=url; link.download=name;
  document.body.appendChild(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),10000);
}
async function api<T>(path:string,method='GET',data?:unknown):Promise<T> {
  const response=await fetch(path,{method,credentials:'omit',headers:{Authorization:'Bearer '+input('token').value.trim(),...(data?{'Content-Type':'application/json'}:{})},...(data?{body:JSON.stringify(data)}:{})});
  const value=await response.json() as T & {error?:string};
  if (!response.ok) throw new Error(value.error||'请求失败'); return value;
}
const errorText=(error:unknown) => error instanceof Error ? error.message : '操作失败';
function report(error:unknown):void {el('status').textContent=errorText(error);}
function mode():void {
  const browser=select('issue-mode').value==='browser';
  el('browser-fields').hidden=!browser;el('csr-fields').hidden=browser;
  el<HTMLTextAreaElement>('csr').required=!browser;
  for(const id of ['leaf-name','pfx-password','pfx-confirm']) input(id).required=browser;
  button('issue-button').textContent=browser?'生成并签发':'签发 CSR';
}
select('issue-mode').onchange=mode;
bindSubjectEditor('leaf-subject','leaf-name');
input('custom-validity').onchange=()=>{
  const custom=input('custom-validity').checked;el('custom-dates').hidden=!custom;input('days').disabled=custom;
  input('leaf-start').required=custom;input('leaf-end').required=custom;
};
const dateText=(ms:number)=>new Date(ms).toISOString().slice(0,19);
input('leaf-start').value=dateText(Date.now()-60000);input('leaf-end').value=dateText(Date.now()+90*86400000);
async function load():Promise<void> {
  try {
    const data=await api<{certificates:CertificateRow[]}>('/api/certificates?offset='+offset);el('rows').replaceChildren();
    for(const c of data.certificates){
      const tr=document.createElement('tr');
      for(const value of [c.subject+' / '+c.serial,c.profile,c.status,c.not_after]){const td=document.createElement('td');td.textContent=value;tr.appendChild(td);}
      const actions=document.createElement('td');
      const view=document.createElement('button');view.textContent='查看 PEM';view.onclick=()=>{el('result').textContent=c.pem;};actions.appendChild(view);
      const cer=document.createElement('button');cer.textContent='下载 CER';cer.onclick=()=>{try{download(unpem(c.pem,'CERTIFICATE'),c.serial+'.cer','application/pkix-cert');}catch(error){report(error);}};actions.appendChild(cer);
      if(c.status==='good'){
        const revoke=document.createElement('button');revoke.textContent='撤销';revoke.onclick=async()=>{
          if(!confirm('永久撤销 '+c.subject+'？'))return;
          const reason=prompt('撤销原因：0 未指定，1 密钥泄露，4 被替代，5 停止使用','0');if(reason===null)return;
          try{await api('/api/certificates/'+c.serial+'/revoke','POST',{reason:Number(reason)});await load();}catch(error){report(error);}
        };actions.appendChild(revoke);
      }
      tr.appendChild(actions);el('rows').appendChild(tr);
    }
    el('page').textContent='第 '+(offset/50+1)+' 页';button('prev').disabled=offset===0;button('next').disabled=data.certificates.length<50;el('status').textContent='已加载 '+data.certificates.length+' 张证书';
  }catch(error){report(error);}
}
button('load').onclick=()=>{offset=0;void load();};button('prev').onclick=()=>{offset=Math.max(0,offset-50);void load();};button('next').onclick=()=>{offset+=50;void load();};
async function pack(password:string):Promise<void> {
  if(!current?.key)throw new Error('当前证书没有浏览器私钥，请使用原私钥另行打包');
  current.pfx=await createPFX(current.issued.certificate,current.issued.chain,current.key,password);
  input('pfx-password').value='';input('pfx-confirm').value='';button('download-pfx').textContent='下载 PFX';
}
el<HTMLFormElement>('issue').onsubmit=async event=>{
  event.preventDefault();if(busy)return;
  if(current?.key&&!current.downloaded&&!confirm('当前 PFX 尚未下载。继续生成会丢失当前页面中的私钥，仍要继续吗？'))return;
  const browser=select('issue-mode').value==='browser';
  let password=input('pfx-password').value;
  let keys:CryptoKeyPair|undefined;
  busy=true;button('issue-button').disabled=true;el('issued-validity').textContent='';
  try{
    if(browser){validatePFXPassword(password);if(password!==input('pfx-confirm').value)throw new Error('两次 PFX 密码不一致');}
    const profile=select('profile').value;
    const validity=input('custom-validity').checked?{notBefore:input('leaf-start').value,notAfter:input('leaf-end').value}:{days:Number(input('days').value)};
    const dnsNames=profile==='server'?{dnsNames:input('dns').value.split(',').map(s=>s.trim()).filter(Boolean)}:{};
    let csr=el<HTMLTextAreaElement>('csr').value;
    if(browser){el('result').textContent='正在浏览器生成密钥和 CSR…';const generated=await browserCSR(input('leaf-name').value,el<HTMLTextAreaElement>('leaf-subject').value.trim());keys=generated.keys;csr=generated.csr;}
    el('result').textContent='正在签发证书…';
    const issued=await api<Issued>('/api/certificates','POST',{csr,profile,...validity,...dnsNames});
    current={issued,key:keys?.privateKey,downloaded:false};
    el('downloads').hidden=false;button('download-pfx').hidden=!browser;
    el('issued-validity').textContent='证书有效期（UTC）：'+issued.notBefore+' → '+issued.notAfter;
    if(browser){
      el('result').textContent='证书已签发，正在本地加密打包 PFX…';
      try{await pack(password);el('result').textContent='CER / PFX 已生成。请下载并保存 PFX 文件及其密码。';}
      catch(error){button('download-pfx').textContent='重新打包并下载 PFX';el('result').textContent='证书已签发，PFX 打包失败：'+errorText(error)+'。请重新填写导出密码，点击重新打包按钮。';}
    }else el('result').textContent=issued.certificate+issued.chain;
    offset=0;await load();
  }catch(error){el('result').textContent=errorText(error);}
  finally{password='';busy=false;button('issue-button').disabled=false;}
};
button('download-cer').onclick=()=>{if(current)download(unpem(current.issued.certificate,'CERTIFICATE'),current.issued.serial+'.cer','application/pkix-cert');};
button('download-pem').onclick=()=>{if(current)download(current.issued.certificate+current.issued.chain,current.issued.serial+'-chain.pem','application/x-pem-file');};
button('download-pfx').onclick=async()=>{
  if(!current||busy)return;busy=true;button('download-pfx').disabled=true;
  try{
    if(!current.pfx){if(input('pfx-password').value!==input('pfx-confirm').value)throw new Error('两次 PFX 密码不一致');await pack(input('pfx-password').value);}
    download(current.pfx!,current.issued.serial+'.pfx','application/x-pkcs12');current.downloaded=true;
  }catch(error){el('result').textContent=errorText(error);}
  finally{busy=false;button('download-pfx').disabled=false;}
};
button('audit').onclick=async()=>{try{el('audit-result').textContent=JSON.stringify(await api('/api/audit'),null,2);}catch(error){report(error);}};
void api<{mode:string}>('/api/setup/status').then(status=>{el('renew-section').hidden=status.mode!=='web';}).catch(()=>{});
for(const service of ['tsa','ocsp'])button('renew-'+service).onclick=async()=>{
  if(!confirm('生成并启用新的 '+service.toUpperCase()+' 证书？'))return;
  button('renew-tsa').disabled=true;button('renew-ocsp').disabled=true;el('renew-status').textContent='正在生成新证书…';
  try{const result=await api<{notAfter:string}>('/api/services/'+service+'/renew','POST',{});el('renew-status').textContent='已启用新证书，到期：'+result.notAfter;await load();}catch(error){el('renew-status').textContent=errorText(error);}
  finally{button('renew-tsa').disabled=false;button('renew-ocsp').disabled=false;}
};
mode();
