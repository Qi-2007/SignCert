import { a, p, OID, HASHES, decode, digest, serial, hex, type CertificateRow, type Context, type Env, assertServiceActive } from './pki';

export const ocspError = (status: number) => new p.OCSPResponse({ responseStatus: new a.Enumerated({ value: status }) }).toSchema().toBER(false);
export async function ocsp(data: ArrayBuffer, env: Env, ctx: Context): Promise<ArrayBuffer> {
  let req: p.OCSPRequest;
  try { req = new p.OCSPRequest({ schema: decode(data) }); } catch { return ocspError(1); }
  if ((req.tbsRequest.version ?? 0) !== 0 || req.tbsRequest.requestorName || req.optionalSignature || req.tbsRequest.requestList.length < 1 || req.tbsRequest.requestList.length > 20) return ocspError(1);
  const extensions = req.tbsRequest.requestExtensions ?? [];
  if (extensions.some(e => e.critical && e.extnID !== OID.nonce) || extensions.filter(e => e.extnID === OID.nonce).length > 1) return ocspError(1);
  const nonce = extensions.find(e => e.extnID === OID.nonce);
  if (nonce) {
    try {
      const n = decode(nonce.extnValue.valueBlock.valueHexView.slice().buffer);
      if (!(n instanceof a.OctetString) || n.valueBlock.valueHexView.length < 1 || n.valueBlock.valueHexView.length > 32) return ocspError(1);
    } catch { return ocspError(1); }
  }
  await assertServiceActive(env, ctx.ocsp);
  await assertServiceActive(env, ctx.ca);
  const now = new Date();
  const nextUpdate = new Date(Math.min(now.getTime() + 300000, ctx.ocsp.notAfter.value.getTime(), ctx.ca.notAfter.value.getTime()));
  const responses: p.SingleResponse[] = [];
  for (const request of req.tbsRequest.requestList) {
    if (request.singleRequestExtensions?.some(e => e.critical)) return ocspError(1);
    const id = request.reqCert;
    const algorithm = id.hashAlgorithm.algorithmId === OID.sha1 ? 'SHA-1' : HASHES[id.hashAlgorithm.algorithmId]?.name;
    if (!algorithm) return ocspError(1);
    let idSerial: string;
    try { idSerial = serial(id.serialNumber); } catch { return ocspError(1); }
    const nameHash = await digest(ctx.ca.subject.toSchema().toBER(false), algorithm);
    const keyHash = await digest(ctx.ca.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView.slice().buffer, algorithm);
    const matches = hex(nameHash) === hex(id.issuerNameHash.valueBlock.valueHexView) && hex(keyHash) === hex(id.issuerKeyHash.valueBlock.valueHexView);
    const row = matches ? await env.DB.prepare('SELECT * FROM certificates WHERE serial=?').bind(idSerial).first<CertificateRow>() : null;
    let status: a.AsnType = new a.Primitive({ idBlock: { tagClass: 3, tagNumber: 2 } });
    if (row?.status === 'revoked') status = new a.Constructed({ idBlock: { tagClass: 3, tagNumber: 1 }, value: [
      new a.GeneralizedTime({ valueDate: new Date(row.revoked_at!) }),
      new a.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [new a.Enumerated({ value: row.revocation_reason ?? 0 })] }),
    ] });
    else if (row?.status === 'good') status = new a.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 } });
    responses.push(new p.SingleResponse({ certID: id, certStatus: status, thisUpdate: now, nextUpdate }));
  }
  const basic = new p.BasicOCSPResponse({ tbsResponseData: new p.ResponseData({ responderID: ctx.ocsp.subject, producedAt: now, responses, ...(nonce ? { responseExtensions: [nonce] } : {}) }), certs: [ctx.ocsp, ctx.ca] });
  await basic.sign(ctx.ocspKey, 'SHA-256');
  return new p.OCSPResponse({ responseStatus: new a.Enumerated({ value: 0 }), responseBytes: new p.ResponseBytes({ responseType: '1.3.6.1.5.5.7.48.1.1', response: new a.OctetString({ valueHex: basic.toSchema().toBER(false) }) }) }).toSchema().toBER(false);
}
