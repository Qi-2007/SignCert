export function subjectEditor(id:string):string {
  return `<details><summary>自定义完整 Subject（可选）</summary><label>Subject 字段<textarea id="${id}" rows="8" maxlength="4096" placeholder="Description = 中文说明&#10;Description = English description&#10;E = testca@example.com&#10;CN = My Certificate&#10;OU = Certification Authority&#10;O = My Organization&#10;L = My City&#10;ST = My Province&#10;C = CN"></textarea></label><small>每行一个字段。L 为城市/地区，S 或 ST 为州/省，C 为两位大写国家代码（例如 CN）。Description 可重复，其他字段仅填写一次；必须包含 CN。完整 Subject 优先于默认名称，留空则沿用原来的 CN。修改已有证书的字段需要重新签发。</small></details>`;
}
export function bindSubjectEditor(id:string,nameId:string):void {
  const field=document.getElementById(id) as HTMLTextAreaElement,name=document.getElementById(nameId) as HTMLInputElement;
  field.oninput=()=>{const value=field.value.match(/^\s*CN\s*=\s*(.+)$/mi)?.[1]?.trim();if(value)name.value=value;};
  name.addEventListener('input',()=>{if(field.value.trim())field.value=field.value.replace(/^(\s*CN\s*=\s*).*$/mi,(_line,prefix:string)=>prefix+name.value);});
}
