import {a,p,commonName} from './pki';
const subjectOIDs:Record<string,string>={C:'2.5.4.6',L:'2.5.4.7',ST:'2.5.4.8',O:'2.5.4.10',OU:'2.5.4.11',CN:'2.5.4.3',E:'1.2.840.113549.1.9.1',Description:'2.5.4.13'};
export function subjectFromText(text:string):p.RelativeDistinguishedNames {
  if(typeof text!=='string'||text.length>4096)throw new Error('Subject 最多 4096 个字符');
  const attributes:p.AttributeTypeAndValue[]=[],seen=new Set<string>();
  for(const line of text.split(/\r?\n/).map(v=>v.trim()).filter(Boolean)) {
    const match=line.match(/^(Description|E|CN|OU|O|L|S|ST|C)\s*=\s*(.+)$/i);
    if(!match)throw new Error('Subject 每行需为 Description/E/CN/OU/O/L/S/ST/C = 值');
    const field=match[1].toUpperCase()==='S'?'ST':match[1];
    const key=Object.keys(subjectOIDs).find(v=>v.toLowerCase()===field.toLowerCase())!,value=match[2].trim();
    if(key!=='Description'&&seen.has(key))throw new Error(key+' 只能填写一次');
    seen.add(key);
    const limit=key==='Description'?1024:key==='E'?254:key==='CN'?128:64;
    if(!value||[...value].length>limit||/[\x00-\x1f\x7f]/.test(value)||new TextDecoder().decode(new TextEncoder().encode(value))!==value)throw new Error(key+' 内容或长度无效');
    if(key==='C'&&!/^[A-Z]{2}$/.test(value))throw new Error('C 必须是两个大写字母，例如 CN');
    if(key==='E'&&(!/^[\x21-\x7e]+$/.test(value)||!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)))throw new Error('E 需要 ASCII 邮箱地址');
    const encoded=key==='C'?new a.PrintableString({value}):key==='E'?new a.IA5String({value}):new a.Utf8String({value});
    attributes.push(new p.AttributeTypeAndValue({type:subjectOIDs[key],value:encoded}));
  }
  if(attributes.length>16)throw new Error('Subject 字段数量过多');
  const result=new p.RelativeDistinguishedNames({typesAndValues:attributes});commonName(result);return result;
}
export function subjectText(subject:p.RelativeDistinguishedNames):string {
  return subject.typesAndValues.map(attribute=>{
    const key=Object.keys(subjectOIDs).find(v=>subjectOIDs[v]===attribute.type);
    if(!key)throw new Error('不支持的 Subject 字段：'+attribute.type);
    const value=attribute.value;
    if(!(value instanceof a.Utf8String||value instanceof a.PrintableString||value instanceof a.IA5String))throw new Error('不支持的 Subject 字符串编码');
    if(/[\r\n]/.test(value.valueBlock.value))throw new Error('Subject 字段不能包含换行');
    return key+' = '+value.valueBlock.value;
  }).join('\n');
}
export const validatedSubject=(subject:p.RelativeDistinguishedNames)=>subjectFromText(subjectText(subject));
