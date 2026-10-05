import { a, p, cn, cert, digest, pem, commonName } from './pki';
import {subjectFromText} from './subject';

export function validatePFXPassword(password: string): void {
  if (password.length < 12 || password.length > 1024 || /[\x00\uD800-\uDFFF]/.test(password)) throw new Error('PFX 密码需要 12–1024 个字符，不支持空字符或 Emoji');
}
export async function browserCSR(name: string, subjectDN?:string): Promise<{keys:CryptoKeyPair;csr:string}> {
  const subject = subjectDN?subjectFromText(subjectDN):cn(name.trim());
  const keys = await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:3072,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
  const publicKey = new p.PublicKeyInfo(); await publicKey.importKey(keys.publicKey);
  const request = new p.CertificationRequest({version:0,subject,subjectPublicKeyInfo:publicKey});
  await request.sign(keys.privateKey,'SHA-256');
  return {keys,csr:pem(request.toSchema().toBER(false),'CERTIFICATE REQUEST')};
}
export function certificateChain(value: string): p.Certificate[] {
  const pattern = /-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----/g;
  const matches = value.match(pattern);
  if (!matches?.length || matches.length > 10 || value.replace(pattern,'').trim()) throw new Error('证书链格式无效');
  return matches.map(cert);
}
async function encryptPFXContent(data: ArrayBuffer,password:ArrayBuffer,iterations:number) {
  // Use primitive DER octets and 16-byte salts for Windows PFX compatibility.
  const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(16));
  const material=await crypto.subtle.importKey('raw',password,'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations},material,{name:'AES-CBC',length:256},false,['encrypt']);
  const ciphertext=await crypto.subtle.encrypt({name:'AES-CBC',iv},key,data);
  const parameters=new p.PBES2Params({
    keyDerivationFunc:new p.AlgorithmIdentifier({algorithmId:'1.2.840.113549.1.5.12',algorithmParams:new p.PBKDF2Params({salt:new a.OctetString({valueHex:salt.buffer}),iterationCount:iterations,prf:new p.AlgorithmIdentifier({algorithmId:'1.2.840.113549.2.9',algorithmParams:new a.Null()})}).toSchema()}),
    encryptionScheme:new p.AlgorithmIdentifier({algorithmId:'2.16.840.1.101.3.4.1.42',algorithmParams:new a.OctetString({valueHex:iv.buffer})}),
  });
  return {algorithm:new p.AlgorithmIdentifier({algorithmId:'1.2.840.113549.1.5.13',algorithmParams:parameters.toSchema()}),ciphertext};
}
export async function createPFX(certificate: string, chainPEM: string, privateKey: CryptoKey, password: string): Promise<ArrayBuffer> {
  validatePFXPassword(password);
  const leaf = cert(certificate), chain = certificateChain(chainPEM);
  const publicKey = await crypto.subtle.importKey('spki',leaf.subjectPublicKeyInfo.toSchema().toBER(false),{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',publicKey,await crypto.subtle.sign('RSASSA-PKCS1-v1_5',privateKey,challenge),challenge)) throw new Error('证书与浏览器私钥不匹配');
  let child = leaf;
  for (const parent of chain) {
    if (!await child.verify(parent)) throw new Error('签发返回的证书链签名无效');
    child = parent;
  }
  if (!await child.verify(child)) throw new Error('证书链缺少有效根证书');
  const passwordBytes = new TextEncoder().encode(password).buffer;
  const id = await digest(leaf.subjectPublicKeyInfo.toSchema().toBER(false));
  const attributes = [
    new p.Attribute({type:'1.2.840.113549.1.9.20',values:[new a.BmpString({value:commonName(leaf.subject).replace(/[\uD800-\uDFFF]/g,'')})]}),
    new p.Attribute({type:'1.2.840.113549.1.9.21',values:[new a.OctetString({valueHex:id.slice(0,20)})]}),
  ];
  const keyEncryption=await encryptPFXContent(await crypto.subtle.exportKey('pkcs8',privateKey),passwordBytes,200000);
  const encryptedKey = new p.PKCS8ShroudedKeyBag({encryptionAlgorithm:keyEncryption.algorithm,encryptedData:new a.OctetString({valueHex:keyEncryption.ciphertext})});
  const keyContents = new p.SafeContents({safeBags:[
    new p.SafeBag({bagId:'1.2.840.113549.1.12.10.1.2',bagValue:encryptedKey,bagAttributes:attributes}),
  ]});
  const certContents = new p.SafeContents({safeBags:[
    ...[leaf,...chain].map((value,index)=>new p.SafeBag({bagId:'1.2.840.113549.1.12.10.1.3',bagValue:new p.CertBag({parsedValue:value}),...(index===0?{bagAttributes:attributes}:{})})),
  ]});
  const certEncryption=await encryptPFXContent(certContents.toSchema().toBER(false),passwordBytes,100000);
  const encryptedCerts = new p.EncryptedData({encryptedContentInfo:new p.EncryptedContentInfo({contentType:'1.2.840.113549.1.7.1',contentEncryptionAlgorithm:certEncryption.algorithm,encryptedContent:new a.OctetString({valueHex:certEncryption.ciphertext})})});
  encryptedCerts.encryptedContentInfo.encryptedContent = new a.OctetString({valueHex:encryptedCerts.encryptedContentInfo.encryptedContent!.getValue()});
  const authenticatedSafe = new p.AuthenticatedSafe({safeContents:[
    new p.ContentInfo({contentType:'1.2.840.113549.1.7.6',content:encryptedCerts.toSchema()}),
    new p.ContentInfo({contentType:'1.2.840.113549.1.7.1',content:new a.OctetString({valueHex:keyContents.toSchema().toBER(false)})}),
  ]});
  const data=authenticatedSafe.toSchema().toBER(false),macSalt=crypto.getRandomValues(new Uint8Array(16));
  const mac=await p.getCrypto(true).stampDataWithPassword({password:passwordBytes,hashAlgorithm:'SHA-256',salt:macSalt.buffer,iterationCount:100000,contentToStamp:data});
  const bundle = new p.PFX({version:3,authSafe:new p.ContentInfo({contentType:'1.2.840.113549.1.7.1',content:new a.OctetString({valueHex:data})}),macData:new p.MacData({
    mac:new p.DigestInfo({digestAlgorithm:new p.AlgorithmIdentifier({algorithmId:'2.16.840.1.101.3.4.2.1',algorithmParams:new a.Null()}),digest:new a.OctetString({valueHex:mac})}),macSalt:new a.OctetString({valueHex:macSalt.buffer}),iterations:100000,
  })});
  return bundle.toSchema().toBER(false);
}
