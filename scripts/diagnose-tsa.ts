import { a, p, OID, cert, decode, digest } from '../src/pki';

const origin = process.argv[2];
if (!origin || new URL(origin).origin !== origin || !origin.startsWith('https://')) throw new Error('Usage: pnpm exec tsx scripts/diagnose-tsa.ts https://your-domain (no token or path)');
const timeout = () => AbortSignal.timeout(20000);
const health = await fetch(origin+'/health',{signal:timeout()});
console.log('Health:',health.status,await health.text());
const certificates = await Promise.all(['root','issuer','tsa'].map(async name => {
  const response = await fetch(origin+'/ca/'+name+'.pem',{signal:timeout()});
  if (!response.ok) throw new Error(name+' certificate HTTP '+response.status);
  const value = cert(await response.text());
  console.log(name,JSON.stringify({notBefore:value.notBefore.value.toISOString(),notAfter:value.notAfter.value.toISOString(),eku:value.extensions?.find(e=>e.extnID==='2.5.29.37')?.parsedValue?.keyPurposes}));
  return value;
}));
const data = new TextEncoder().encode('Signcert public TSA diagnostic '+crypto.randomUUID()).buffer;
const nonce = new a.Integer({value:1234567});
const request = new p.TimeStampReq({version:1,certReq:true,nonce,messageImprint:new p.MessageImprint({hashAlgorithm:new p.AlgorithmIdentifier({algorithmId:OID.sha256}),hashedMessage:new a.OctetString({valueHex:await digest(data)})})});
const response = await fetch(origin+'/tsa',{method:'POST',headers:{'Content-Type':'application/timestamp-query'},body:request.toSchema().toBER(false),signal:timeout()});
console.log('RFC3161 HTTP:',response.status,response.headers.get('Content-Type'));
const bytes = await response.arrayBuffer();
if (!response.ok || !response.headers.get('Content-Type')?.includes('application/timestamp-reply')) throw new Error(new TextDecoder().decode(bytes).slice(0,500));
const parsed = new p.TimeStampResp({schema:decode(bytes)});
console.log('RFC3161 status:',parsed.status.status,parsed.status.statusStrings?.map(value=>value.valueBlock.value));
if (!parsed.timeStampToken || parsed.status.status !== 0) throw new Error('TSA rejected request');
const sd = new p.SignedData({schema:parsed.timeStampToken.content});
const info = new p.TSTInfo({schema:decode(sd.encapContentInfo.eContent!.getValue())});
console.log('RFC3161 verification:',await sd.verify({signer:0,data,checkChain:true,trustedCerts:[certificates[0]]}));
console.log('Timestamp:',info.genTime.toISOString(),'nonce matches:',info.nonce?.valueBlock.valueDec===1234567,'certificates:',sd.certificates?.length);

// Legacy Authenticode uses a base64 SPC request with a signature-sized payload.
const payload = crypto.getRandomValues(new Uint8Array(256)).buffer;
const legacyRequest = new a.Sequence({value:[new a.ObjectIdentifier({value:'1.3.6.1.4.1.311.3.2.1'}),new a.Sequence({value:[new a.ObjectIdentifier({value:'1.2.840.113549.1.7.1'}),new a.Constructed({idBlock:{tagClass:3,tagNumber:0},value:[new a.OctetString({valueHex:payload})]})]})]}).toBER(false);
const legacy = await fetch(origin+'/tsa',{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:Buffer.from(legacyRequest).toString('base64'),signal:timeout()});
console.log('Authenticode HTTP:',legacy.status,legacy.headers.get('Content-Type'));
const legacyText = await legacy.text();
if (!legacy.ok) throw new Error(legacyText.slice(0,500));
const content = new p.ContentInfo({schema:decode(Uint8Array.from(Buffer.from(legacyText,'base64')).buffer)});
const signed = new p.SignedData({schema:content.content});
console.log('Authenticode CMS verification:',await signed.verify({signer:0,checkChain:true,trustedCerts:[certificates[0]]}));
