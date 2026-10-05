import { a, p, decode, digest, privateKey, base64, assertServiceActive, serial, randomSerial, hex, type Env, type Context } from './pki';

export async function authenticode(input: ArrayBuffer, env: Env, ctx: Context, customTime?: Date): Promise<string> {
  // Windows CRYPT_STRING_BASE64 output can include CRLF and a C-string NUL
  // terminator in Content-Length. Only discard NULs at the end, not inside data.
  const text = new TextDecoder().decode(input).replace(/[\s\0]+$/, '').replace(/\s/g, '');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text)) throw new Error('Expected base64');
  const der = Uint8Array.from(atob(text), c => c.charCodeAt(0)).buffer;
  const schema = decode(der);
  if (!(schema instanceof a.Sequence)) throw new Error('Expected sequence');
  const fields = schema.valueBlock.value;
  if (!(fields[0] instanceof a.ObjectIdentifier)) throw new Error('Expected OID');
  let octets: a.OctetString;
  if (fields[0].valueBlock.toString() === '1.3.6.1.4.1.311.3.2.1') {
    if (fields.length !== 2 || !(fields[1] instanceof a.Sequence)) throw new Error('Invalid SPC request');
    const inner = fields[1].valueBlock.value;
    if (inner.length !== 2 || !(inner[0] instanceof a.ObjectIdentifier) || inner[0].valueBlock.toString() !== '1.2.840.113549.1.7.1' || !(inner[1] instanceof a.Constructed) || inner[1].idBlock.tagClass !== 3 || inner[1].idBlock.tagNumber !== 0 || inner[1].valueBlock.value.length !== 1 || !(inner[1].valueBlock.value[0] instanceof a.OctetString)) throw new Error('Invalid SPC content');
    octets = inner[1].valueBlock.value[0];
  } else if (fields[0].valueBlock.toString() === '1.2.840.113549.1.7.2') {
    const content = new p.ContentInfo({ schema }); const sd = new p.SignedData({ schema: content.content });
    if (sd.encapContentInfo.eContentType !== '1.2.840.113549.1.7.1' || !sd.encapContentInfo.eContent) throw new Error('Invalid PKCS7 content');
    octets = sd.encapContentInfo.eContent;
  } else throw new Error('Unknown request OID');
  const payload = octets.getValue();
  if (!payload.byteLength || payload.byteLength > 8192) throw new Error('Invalid signature size');
  await assertServiceActive(env, ctx.ca); await assertServiceActive(env, ctx.tsa);
  const receivedAt = new Date(), signTime = customTime ?? receivedAt;
  const attrs = [
    new p.Attribute({ type: '1.2.840.113549.1.9.3', values: [new a.ObjectIdentifier({ value: '1.2.840.113549.1.7.1' })] }),
    new p.Attribute({ type: '1.2.840.113549.1.9.4', values: [new a.OctetString({ valueHex: await digest(payload, 'SHA-1') })] }),
    new p.Attribute({ type: '1.2.840.113549.1.9.5', values: [signTime.getUTCFullYear() >= 1950 && signTime.getUTCFullYear() < 2050 ? new a.UTCTime({ valueDate: signTime }) : new a.GeneralizedTime({ valueDate: signTime })] }),
  ];
  attrs.sort((l, r) => { const x = new Uint8Array(l.toSchema().toBER(false)), y = new Uint8Array(r.toSchema().toBER(false)); for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i]; return x.length - y.length; });
  const sd = new p.SignedData({ version: 1, encapContentInfo: new p.EncapsulatedContentInfo({ eContentType: '1.2.840.113549.1.7.1' }), certificates: [ctx.tsa, ctx.ca], signerInfos: [new p.SignerInfo({ version: 1, sid: new p.IssuerAndSerialNumber({ issuer: ctx.tsa.issuer, serialNumber: ctx.tsa.serialNumber }), signedAttrs: new p.SignedAndUnsignedAttributes({ type: 0, attributes: attrs }) })] });
  sd.encapContentInfo.eContent = new a.OctetString({ valueHex: payload });
  await sd.sign(await privateKey(env.TSA_KEY, 'SHA-1'), 0, 'SHA-1');
  const response = new p.ContentInfo({ contentType: '1.2.840.113549.1.7.2', content: sd.toSchema(true) }).toSchema().toBER(false);
  const id = serial(randomSerial());
  await env.DB.batch([
    env.DB.prepare('INSERT INTO timestamps (serial,at,received_at,time_mode,hash_algorithm,imprint,token_sha256) VALUES (?,?,?,?,?,?,?)').bind(id, signTime.toISOString(), receivedAt.toISOString(), customTime ? 'custom' : 'current', 'SHA-1/Authenticode', hex(await digest(payload, 'SHA-1')), hex(await digest(response))),
    ...(customTime ? [env.DB.prepare('INSERT INTO audit (action,serial,at,detail) VALUES (?,?,?,?)').bind('timestamp-custom', id, receivedAt.toISOString(), JSON.stringify({ requestedTime: signTime.toISOString(), protocol: 'Authenticode' }))] : []),
  ]);
  return base64(response);
}
