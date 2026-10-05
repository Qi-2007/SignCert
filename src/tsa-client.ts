interface TSAConfiguration {mode:string;serial:string;subject:string;status:string;notBefore:string;notAfter:string;issuer:{subject:string;notBefore:string;notAfter:string};endpoint:string;customTimeEnabled:boolean;customTokenRequired:boolean;policy:string}
const el = <T = HTMLElement>(id:string) => document.getElementById(id) as T;
const input = (id:string) => el<HTMLInputElement>(id);
const button = (id:string) => el<HTMLButtonElement>(id);
let current:TSAConfiguration|undefined, busy=false;
let pending:{subject:string;notBefore:string;notAfter:string;expectedSerial:string}|undefined;
const text = (error:unknown) => error instanceof Error ? error.message : '操作失败';
const dateText = (value:string|number) => new Date(value).toISOString().slice(0,19);
async function api<T>(path:string,data?:unknown):Promise<T> {
  const response = await fetch(path,{method:data?'POST':'GET',credentials:'omit',headers:{Authorization:'Bearer '+input('token').value.trim(),...(data?{'Content-Type':'application/json'}:{})},...(data?{body:JSON.stringify(data)}:{})});
  const value = await response.json() as T & {error?:string};
  if (!response.ok) throw new Error(value.error ?? '请求失败'); return value;
}
function render(value:TSAConfiguration):void {
  current=value;el('current').hidden=false;el('configuration').hidden=false;
  el('current-info').textContent='名称：'+value.subject+'\n序列号：'+value.serial+'\n状态：'+value.status+'\n生效（UTC）：'+value.notBefore+'\n到期（UTC）：'+value.notAfter+'\n时间戳接口：'+value.endpoint+'\n自定义时间：'+(value.customTimeEnabled?'已启用':'未启用')+'\n自定义时间请求：'+(value.customTokenRequired?'需要自定义时间戳令牌':'无需令牌，允许匿名请求')+'\n策略 OID：'+value.policy;
  el('issuer-info').textContent='中间 CA：'+value.issuer.subject+'\n允许范围（UTC）：'+value.issuer.notBefore+' → '+value.issuer.notAfter;
  input('name').value=value.subject;input('start').value=dateText(value.notBefore);input('end').value=dateText(value.notAfter);
  el<HTMLFieldSetElement>('fields').disabled=value.mode!=='web';
  el('status').textContent=value.mode==='web'?'已加载当前 TSA，可以配置重新签发。':'当前为 Secrets 模式；在线重新签发仅支持 Web 初始化模式，请使用离线续签脚本。';
}
function lock(value:boolean):void {busy=value;button('load').disabled=value;el<HTMLFieldSetElement>('fields').disabled=value||current?.mode!=='web';input('token').disabled=value;}
button('load').onclick=async()=>{
  if(busy)return;lock(true);el('result').textContent='';
  try {render(await api<TSAConfiguration>('/api/services/tsa'));}
  catch(error){current=undefined;el('current').hidden=true;el('configuration').hidden=true;el('status').textContent=text(error);}
  finally{lock(false);}
};
input('token').oninput=()=>{current=undefined;el('current').hidden=true;el('configuration').hidden=true;el('status').textContent='令牌已更改，请重新加载当前 TSA。';};
button('issuer-dates').onclick=()=>{if(current){input('start').value=dateText(current.issuer.notBefore);input('end').value=dateText(current.issuer.notAfter);}};
button('default-dates').onclick=()=>{if(current){input('start').value=dateText(Math.max(Date.now()-60000,Date.parse(current.issuer.notBefore)));input('end').value=dateText(Math.min(Date.now()+365*86400000,Date.parse(current.issuer.notAfter)));}};
el<HTMLFormElement>('issue').onsubmit=async event=>{
  event.preventDefault();if(busy||!current||current.mode!=='web')return;
  const notBefore=input('start').value,notAfter=input('end').value,subject=input('name').value.trim();
  const start=Date.parse(notBefore+'Z'),end=Date.parse(notAfter+'Z'),now=Date.now();
  if(!subject||!Number.isFinite(start)||!Number.isFinite(end)||start>=end||start<Date.parse(current.issuer.notBefore)||end>Date.parse(current.issuer.notAfter)||start>now||end<=now){el('result').textContent='请检查名称与日期：有效期须位于中间 CA 内、覆盖当前时间，且生效早于到期。';return;}
  pending={subject,notBefore,notAfter,expectedSerial:current.serial};
  el('preview').textContent='名称：'+subject+'\n生效（UTC）：'+notBefore+'\n到期（UTC）：'+notAfter+'\n将替换序列号：'+current.serial;
  el('confirmation').hidden=false;el<HTMLFieldSetElement>('fields').disabled=true;button('load').disabled=true;input('token').disabled=true;
};
button('cancel-issue').onclick=()=>{if(busy)return;pending=undefined;el('confirmation').hidden=true;lock(false);};
button('confirm-issue').onclick=async()=>{
  if(busy||!pending)return;
  const request=pending;pending=undefined;el('confirmation').hidden=true;lock(true);el('result').textContent='正在生成新密钥并重新签发 TSA…';
  try{
    const issued=await api<{serial:string;notBefore:string;notAfter:string}>('/api/services/tsa/renew',request);
    el('result').textContent='新 TSA 已签发并启用。序列号：'+issued.serial+'；有效期（UTC）：'+issued.notBefore+' → '+issued.notAfter;
    try {render(await api<TSAConfiguration>('/api/services/tsa'));} catch(error){current=undefined;el('status').textContent='签发成功，重新加载失败：'+text(error)+'。请点击加载当前 TSA 核对。';}
  }catch(error){el('result').textContent=text(error);}
  finally{lock(false);}
};
