import { a, p, OID, HASHES, decode, digest, randomSerial, serial, hex, type Context, type Env, assertServiceActive } from './pki';

export function failure(bit: number, message: string): ArrayBuffer {
  const bits = new Uint8Array(Math.floor(bit / 8) + 1);
  bits[Math.floor(bit / 8)] = 0x80 >> (bit % 8);
  return new p.TimeStampResp({ status: new p.PKIStatusInfo({ status: 2, statusStrings: [new a.Utf8String({ value: message })], failInfo: new a.BitString({ valueHex: bits.buffer, unusedBits: 7 - bit % 8 }) }) }).toSchema().toBER(false);
}
export async function timestamp(data: ArrayBuffer, env: Env, ctx: Context, customTime?: Date): Promise<ArrayBuffer> {
  let req: p.TimeStampReq;
  try { req = new p.TimeStampReq({ schema: decode(data) }); } catch { return failure(5, 'Malformed request'); }
  if (req.version !== 1) return failure(5, 'Unsupported version');
  const hash = HASHES[req.messageImprint.hashAlgorithm.algorithmId];
  if (!hash) return failure(0, 'Unsupported digest algorithm');
  if (req.messageImprint.hashedMessage.valueBlock.valueHexView.length !== hash.size) return failure(5, 'Incorrect digest length');
  if (req.reqPolicy && req.reqPolicy !== env.TSA_POLICY_OID) return failure(15, 'Unknown TSA policy');
  if (req.extensions?.length) return failure(16, 'Request extensions unsupported');
  if (req.nonce && (req.nonce.valueBlock.valueHexView.length > 32 || req.nonce.valueBlock.valueHexView[0] & 128)) return failure(5, 'Invalid nonce');
  await assertServiceActive(env, ctx.tsa);
  await assertServiceActive(env, ctx.ca);
  const receivedAt = new Date();
  const info = new p.TSTInfo({ version: 1, policy: env.TSA_POLICY_OID, messageImprint: req.messageImprint, serialNumber: randomSerial(), genTime: customTime ?? receivedAt, ...(req.nonce ? { nonce: req.nonce } : {}) });
  const content = info.toSchema().toBER(false);
  // ESS SigningCertificateV2: SHA-256 is the default hashAlgorithm (RFC 5816).
  const signingCertificate = new a.Sequence({ value: [new a.Sequence({ value: [new a.Sequence({ value: [new a.OctetString({ valueHex: await digest(ctx.tsa.toSchema(true).toBER(false)) })] })] })] });
  const attrs = [
    new p.Attribute({ type: '1.2.840.113549.1.9.3', values: [new a.ObjectIdentifier({ value: OID.tst })] }),
    new p.Attribute({ type: '1.2.840.113549.1.9.4', values: [new a.OctetString({ valueHex: await digest(content) })] }),
    new p.Attribute({ type: '1.2.840.113549.1.9.16.2.47', values: [signingCertificate] }),
  ];
  // DER SET OF ordering is lexicographic over encoded attributes.
  attrs.sort((x, y) => {
    const l = new Uint8Array(x.toSchema().toBER(false)), r = new Uint8Array(y.toSchema().toBER(false));
    for (let i = 0; i < Math.min(l.length, r.length); i++) if (l[i] !== r[i]) return l[i] - r[i];
    return l.length - r.length;
  });
  const sd = new p.SignedData({ version: 3,
    encapContentInfo: new p.EncapsulatedContentInfo({ eContentType: OID.tst, eContent: new a.OctetString({ valueHex: content }) }),
    ...(req.certReq ? { certificates: [ctx.tsa, ctx.ca] } : {}),
    signerInfos: [new p.SignerInfo({ version: 1, sid: new p.IssuerAndSerialNumber({ issuer: ctx.tsa.issuer, serialNumber: ctx.tsa.serialNumber }), signedAttrs: new p.SignedAndUnsignedAttributes({ type: 0, attributes: attrs }) })],
  });
  // PKI.js converts an OCTET STRING to BER constructed form in its constructor.
  // RFC 3161 clients require DER; keep the encapsulated content primitive.
  sd.encapContentInfo.eContent = new a.OctetString({ valueHex: content });
  await sd.sign(ctx.tsaKey, 0, 'SHA-256');
  const response = new p.TimeStampResp({ status: new p.PKIStatusInfo({ status: 0 }), timeStampToken: new p.ContentInfo({ contentType: '1.2.840.113549.1.7.2', content: sd.toSchema(true) }) }).toSchema().toBER(false);
  await env.DB.batch([
    env.DB.prepare('INSERT INTO timestamps (serial,at,received_at,time_mode,hash_algorithm,imprint,token_sha256) VALUES (?,?,?,?,?,?,?)')
      .bind(serial(info.serialNumber), info.genTime.toISOString(), receivedAt.toISOString(), customTime ? 'custom' : 'current', hash.name, hex(req.messageImprint.hashedMessage.valueBlock.valueHexView), hex(await digest(response))),
    ...(customTime ? [env.DB.prepare('INSERT INTO audit (action,serial,at,detail) VALUES (?,?,?,?)').bind('timestamp-custom', serial(info.serialNumber), receivedAt.toISOString(), JSON.stringify({ requestedTime: info.genTime.toISOString() }))] : []),
  ]);
  return response;
}
