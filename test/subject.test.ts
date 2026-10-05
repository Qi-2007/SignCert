import {test} from 'node:test';
import assert from 'node:assert/strict';
import {X509Certificate} from 'node:crypto';
import {a,p,rsaKeys,makeCert,certPEM} from '../src/pki';
import {subjectFromText,subjectText,validatedSubject} from '../src/subject';
export const exampleSubject='Description = 皮卡丘公共服务测试根证书 RSA\nDescription = Pikachu Public Test Root RSA\nE = testca@certs.us.kg\nCN = Pikachu Test CA RSA\nOU = Pikachu Certification Authority\nO = Pikachu Trust Network CA\nC = CN';
test('complete Subject retains repeated descriptions and encodes country and email correctly',async()=>{
  const subject=subjectFromText(exampleSubject);
  assert.equal(subjectText(subject),exampleSubject);
  assert.equal(subject.typesAndValues.filter(v=>v.type==='2.5.4.13').length,2);
  assert.ok(subject.typesAndValues.find(v=>v.type==='2.5.4.6')!.value instanceof a.PrintableString);
  assert.ok(subject.typesAndValues.find(v=>v.type==='1.2.840.113549.1.9.1')!.value instanceof a.IA5String);
  const keys=await rsaKeys(),pub=new p.PublicKeyInfo();await pub.importKey(keys.publicKey);
  const certificate=await makeCert({subject,publicKey:pub,signingKey:keys.privateKey,profile:'root',days:365});
  const independent=new X509Certificate(certPEM(certificate));
  assert.equal(independent.verify(independent.publicKey),true);
  for(const value of ['皮卡丘公共服务测试根证书 RSA','Pikachu Public Test Root RSA','testca@certs.us.kg','Pikachu Test CA RSA','Pikachu Certification Authority','Pikachu Trust Network CA'])assert.ok(independent.subject.includes(value));
  assert.ok(independent.subjectAltName!.includes('email:testca@certs.us.kg'));
  assert.equal(subjectText(validatedSubject(subject)),exampleSubject);
});
test('Subject rejects ambiguous, unsupported and invalid fields',()=>{
  for(const value of ['O = Missing CN','CN = a\nCN = b','CN = a\nC = China','CN = a\nC = Teyvat','CN = a\nE = 中文@example.com','CN = a\nE = invalid','CN = a\nUID = unsupported','CN = a\nS = one\nST = two','CN = a\nL = one\nl = two','CN = a\nDescription = bad\0value','CN = a\nO = '+ 'x'.repeat(65),'CN = a\nDescription = '+ 'x'.repeat(1025)])assert.throws(()=>subjectFromText(value));
});
test('locality and state aliases survive certificate encoding and CSR subject validation',async()=>{
  const text='Description = Qi SignCert Root CA\nE = 1435990998@qq.com\nOU = Akademiya\nO = Nahida\nL = Sanctuary of Surasthana\nS = Sumeru\nC = CN\nCN = Qi SignCert Root CA';
  const subject=subjectFromText(text),canonical=text.replace('S = Sumeru','ST = Sumeru');
  assert.equal(subjectText(subject),canonical);
  assert.equal(subjectText(validatedSubject(subject)),canonical);
  assert.equal(subjectText(subjectFromText(text.replace('S = Sumeru','st = Sumeru'))),canonical);
  assert.ok(subject.typesAndValues.find(v=>v.type==='2.5.4.7')!.value instanceof a.Utf8String);
  assert.ok(subject.typesAndValues.find(v=>v.type==='2.5.4.8')!.value instanceof a.Utf8String);
  const keys=await rsaKeys(),pub=new p.PublicKeyInfo();await pub.importKey(keys.publicKey);
  const certificate=await makeCert({subject,publicKey:pub,signingKey:keys.privateKey,profile:'root',days:365});
  const independent=new X509Certificate(certPEM(certificate));
  assert.equal(independent.verify(independent.publicKey),true);
  assert.ok(independent.subject.includes('L=Sanctuary of Surasthana'));
  assert.ok(independent.subject.includes('ST=Sumeru'));
  assert.equal(subjectText(subjectFromText('CN = 中文测试\nL = 广州\nS = 广东')),'CN = 中文测试\nL = 广州\nST = 广东');
});
