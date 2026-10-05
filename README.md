# Signcert — Cloudflare Workers 私有证书系统

由 [FakeSign/TSWorker](https://github.com/PIKACHUIM/FakeSign/tree/main/TSWorker) 的部署方式和接口设计扩展而来。使用 TypeScript、PKI.js、ASN1.js、Workers WebCrypto 和 D1；无需在 Worker 内运行 OpenSSL。

支持部署后在 `/setup` 页面初始化：浏览器生成根 CA、签发 CA、TSA 和 OCSP，下载加密备份后启用服务。提供 CSR 签发、撤销、CRL、证书下载、审计与中文管理页面。保留上游自定义时间路径和传统 Authenticode 协议，同时实现 RFC 3161 的 ESSCertIDv2、nonce、policy、摘要长度及错误码处理。

这是一套私有 PKI：客户端需要自行信任根证书。自建 CA 不会自动获得 Windows、浏览器或公开代码签名信任。当前未实现 ACME、公开 CA 审核、HSM 或多租户权限。

## 结构

```text
离线根 CA（浏览器生成，私钥仅进入本地加密备份）
└─ 在线签发 CA（D1 加密存储，pathLen=0）
   ├─ TSA（独立 RSA 密钥，critical timeStamping EKU）
   ├─ OCSP 响应者（独立 RSA 密钥，OCSPSigning EKU）
   └─ 代码签名 / TLS 服务端 / 客户端认证证书

Workers：签发、时间戳、OCSP、CRL、管理页面
D1：加密服务配置、证书、永久撤销、审计、时间戳摘要、CRL 编号
Worker Secret：PKI_MASTER_KEY（初始化认证和配置解密）
```

CA/TSA/OCSP 密钥使用 RSA-3072。叶证书接受 RSA-2048～4096（e=65537）或 EC P-256/P-384 CSR。默认签发 90 天，最大有效期由 `MAX_VALIDITY_DAYS` 配置（示例为 365 天）；到期时间受签发 CA 限制。CSR 必须通过签名验证；不复制 CSR 内的 CA/EKU/SAN 扩展，扩展由服务端用途模板生成，TLS DNS 名称由管理员显式指定。SAN 暂不支持 IP/邮箱/URI。

## 本地启动（PowerShell）

需要 Node.js 22+ 与 pnpm 11。依赖版本由 `pnpm-lock.yaml` 固定。

```powershell
pnpm install --frozen-lockfile
# 新克隆的仓库先复制配置模板；已有 wrangler.toml 时不要覆盖。
if (-not (Test-Path wrangler.toml)) { Copy-Item wrangler.example.toml wrangler.toml }
pnpm check
pnpm test

# 创建本地开发主密钥（不会打印），写入已被 Git 忽略的文件。
$devMaster = [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
[IO.File]::WriteAllText((Join-Path $PWD '.dev.vars'), "PKI_MASTER_KEY=$devMaster`n")
pnpm db:local
pnpm dev
```

访问 `http://localhost:8787/setup`，输入 `$devMaster` 的值作为初始化主密钥，设置系统名称与至少 16 字符的备份密码。页面先生成证书，再提供下载按钮；下载备份并勾选已保存后才能提交。WebCrypto 需要现代浏览器以及 HTTPS 或 localhost。已有 `.dev.vars` 时保留原内容，不要用上面的开发命令覆盖它。开发与生产使用不同主密钥和数据库。

Web 模式的根私钥不会上传 Worker。`signcert-backup.json` 包含根私钥、全部在线密钥和访问令牌，使用独立备份密码通过 PBKDF2-SHA256（600000 次）和 AES-256-GCM 加密。页面不会发送备份密码。根证书和证书链可另行下载为 PEM；管理令牌与自定义时间戳令牌在初始化成功后显示，也在加密备份中。保管备份文件和密码；浏览器刷新后不能凭空找回根私钥。

## 部署到 Cloudflare

先确定长期使用的域名：证书签发时会写入 AIA 和 CRL 地址，改变域名需要保留原地址或重新签发证书。

```powershell
pnpm exec wrangler login
pnpm exec wrangler d1 create signcert
```

将输出的数据库 ID 写入 `wrangler.toml` 的 `database_id`，将 `PUBLIC_URL` 改为你的 HTTPS 域名，并启用文件内的 `[[routes]]` / `custom_domain` 示例。`workers_dev=false`、`preview_urls=false` 默认禁用替代访问域名。

修改 `TSA_POLICY_OID` 为你管理的 policy OID；示例值仅供私有测试。协议由 policy 标识服务政策，政策应说明时间来源、精度、密钥与自定义时间行为。

```powershell
pnpm db:remote
pnpm deploy
pnpm exec wrangler secret put PKI_MASTER_KEY
```

最后一条命令提示输入一个 **64 位十六进制随机主密钥**。从密码管理器或 `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"` 生成，并保存在自己的密码管理器中；也可在 Cloudflare Dashboard 的 Worker Settings → Variables and Secrets 设置同名 Secret。主密钥用于首次初始化身份验证，以及通过 HKDF 派生 D1 配置加密密钥，**初始化后不能随意删除或修改，否则服务无法解密配置**。主密钥不会写入 D1。

然后访问 `https://你的域名/setup`，输入同一主密钥，生成证书、下载加密备份并完成初始化。无需本地执行 `bootstrap`、上传证书 Secrets 或导入 `seed.sql`。提交时 Worker 校验证书链、用途、密钥匹配和有效期，D1 一次事务写入加密配置与服务证书；重复或并发初始化不会覆盖已有系统。未初始化时 `/admin` 和首页会跳转 `/setup`，`/health` 返回 `uninitialized`；成功后返回 `ready`。

使用 `pnpm deploy`，它会先构建浏览器初始化脚本再部署。直接执行裸 `wrangler deploy` 前须运行 `pnpm build:client`，否则新机器缺少生成的浏览器资源。

管理页面与 `/api/*` 使用初始化生成的独立管理令牌；可额外配置 Cloudflare Access 保护 `/setup*`、`/admin*` 和 `/api/*`，避免拦截公共时间戳/OCSP/CRL 客户端。公共签名端点应按实际流量配置 Cloudflare 限流。

`wrangler.toml` 是本地部署配置，不提交 Git；仓库提供 `wrangler.example.toml` 模板，部署前替换域名和 D1 ID。D1 导出、密钥、PFX、加密备份、构建产物和本地测试缓存也不提交。已有 Secrets 模式的证书系统继续使用原证书和密钥；Web 初始化会拒绝覆盖已有 Secrets 或已有签发记录，不会重新生成你的 CA。

## 离线脚本模式（可选，兼容旧部署）

如果希望使用本地初始化脚本而非 Web 页面，原流程仍可用：设置 `ROOT_PASSPHRASE` 后执行 `pnpm bootstrap https://你的域名`，执行数据库迁移并导入 `pki/seed.sql`，然后 `pnpm build:client` 和 `pnpm exec wrangler deploy --secrets-file pki/secrets.json`。`pki/root-encrypted.key` 是 AES-256-CBC 加密 PKCS#8 根私钥；根私钥不包含在上传的 Secrets JSON 中。`pki/` 和 `.dev.vars` 都已忽略，Windows 文件权限请使用受限账户目录和 NTFS ACL 保护。

## 自定义证书有效期

首次初始化的 `/setup` 页面可分别设置根 CA、签发 CA 的生效与到期时间；默认仍为当前时间前 1 分钟开始、根 CA 3650 天、签发 CA 1825 天。日期输入按 **UTC** 处理，例如北京时间 `2020-01-01 08:00:00` 应填 `2020-01-01 00:00:00`。签发 CA 必须位于根 CA 有效期内，且两张 CA 均需覆盖当前时间以启用在线服务。生成或恢复备份后页面显示实际证书日期供核对。已有证书的日期是签名内容，不能原地修改；此设置用于生成新证书，不会覆盖已初始化的 CA。

`/admin` 签发代码签名、TLS 或客户端证书时，勾选“自定义生效与到期时间”，可填写精确起止时间。API 请求使用 `notBefore` 和 `notAfter` 两个字段，接受 `YYYY-MM-DDTHH:mm:ss`（可省略秒或附加 `Z`）；不接受时区偏移，两者均按 UTC 解析，不能同时发送 `days`。例如 `{ "csr": "…", "profile": "code-signing", "notBefore": "2020-01-01T00:00:00Z", "notAfter": "2020-04-01T00:00:00Z" }`。整个区间必须位于签发 CA 内，长度不超过 `MAX_VALIDITY_DAYS`；日期越界会被拒绝，不会自动改写。未指定起止时间则沿用按天数签发的流程。允许历史或未来的叶证书，但客户端仍会检查有效期。

证书日期与时间戳声明分别设置。回溯 CA 或叶证书日期不会自动回溯 TSA/OCSP 证书；TSA/OCSP 默认从当前时间开始有效，到期不超过签发 CA。历史时间戳是否被客户端接受仍需验证完整证书链。

## 自定义时间戳

可在 Worker 环境变量中配置 `TSA_CUSTOM_TOKEN_REQUIRED`：未设置或设为 `"true"` 时要求自定义时间戳令牌；只有明确设为 `"false"` 才允许匿名自定义时间请求。如需匿名模式，在自己的 `wrangler.toml` 中设为 `"false"`，重新部署后生效；同时仍需 `TSA_FAKE = "true"`。匿名模式下任何人都可指定时间调用 TSA，管理、证书签发和 TSA 重新签发接口仍需要管理令牌。`/admin/tsa` 加载后显示当前令牌要求。无需重建证书或迁移数据库。

匿名模式命令示例（日期后的斜杠可保留）：

```powershell
signtool timestamp /tr "http://cert.example.com/2022-11-03T21:14:19/" /td SHA256 cmp90hxgen2.exe
```

设置 `wrangler.toml` 中 `TSA_FAKE="true"` 后重新部署。真实时间请求仍使用 `/` 或 `/tsa`；自定义请求兼容上游 `/{datetime}`，也支持 `/tsa/{datetime}`。日期必须是严格 UTC，接受 `yyyy-MM-ddTHH:mm:ss`、末尾 `Z` 和三位毫秒；省略 `Z` 仍按 UTC 解析，不使用本地时区。

要求令牌的模式下，自定义请求需要初始化生成的 `TSA_CUSTOM_TOKEN`，通过 `X-TSA-Token` 请求头传递，或为了 signtool 兼容使用查询参数 `?token=...`。它是“自定义时间戳令牌”，不是管理令牌或 `PKI_MASTER_KEY`。日期路径支持尾部斜杠，例如 `/2022-11-03T21:14:19/?token=...` 与不带尾部斜杠的路径等效，`/tsa/` 也可用于当前时间请求。旧部署的日期路径带斜杠会返回 404；要求令牌的模式下没有自定义时间令牌会返回 401，这两种错误都可能被 SignTool 显示为服务器不可达或响应无效。查询参数可能被客户端/代理/平台访问日志记录，优先使用请求头；有暴露时轮换这个独立令牌。

```powershell
# 使用 signtool 时，URL 包含独立 TSA 令牌
$tsaToken = [System.Net.NetworkCredential]::new('', (Read-Host '输入初始化页面显示的时间戳令牌' -AsSecureString)).Password
signtool sign /tr "https://pki.example.com/2020-01-01T00:00:00?token=$tsaToken" /td SHA256 /fd SHA256 /f app.pfx app.exe
```

自定义时间会写入 RFC 3161 的 `genTime` 或传统 Authenticode 的 `signingTime`。D1 同时保存指定时间、实际请求时间、`time_mode=custom` 和审计事件。该模式生成的是你指定的时间声明，不能当作真实时间证明；若日期不在 TSA 或证书链有效期内，签名结构有效也可能被客户端拒绝。本服务不会自动修改证书有效期。正常模式使用 Worker 的 UTC 时钟；未提供外部校时证明或保证精度。

`MAX_VALIDITY_DAYS` 必须是正的安全整数，默认 `365`。私有 CA 没有硬编码的 825 天上限；如需长有效期，可在 `wrangler.toml` 中设置 `MAX_VALIDITY_DAYS = "7300"` 后重新部署。该配置限制完整的生效至到期区间，历史时间也计入长度，且不能超出签发 CA 的有效期。服务端配置错误会明确指出 `MAX_VALIDITY_DAYS`；调整此变量无需重置 PKI。

时间戳故障诊断可运行 `pnpm exec tsx scripts/diagnose-tsa.ts https://你的域名`。脚本无需管理令牌，检查健康状态、公开 CA/TSA 日期，并分别发送一次当前时间的 RFC 3161 和 Authenticode 测试请求，校验 CMS 签名与证书链；会新增两条正常时间戳记录。它不替代 Windows 签名工具的最终验证，也不导入系统信任。自定义历史时间若早于 TSA 证书生效时间，客户端可能拒绝时间戳，即使服务端成功返回。

TSA 独立配置页面为 `/admin/tsa`，也可从管理页的“服务证书续期”进入。输入管理令牌并加载当前证书，填写名称与 UTC 启止时间，或点击“使用中间 CA 的完整有效期”；预览确认后重新签发并立即替换在线 TSA 配置和私钥。有效期需位于中间 CA 内并覆盖当前时间；TSA 不受叶证书 `MAX_VALIDITY_DAYS` 限制。旧 TSA 证书及状态、时间戳记录保留，不会撤销或重新签名历史响应。根 CA、中间 CA、访问令牌保持不变，无需重置数据库。仅支持 Web 初始化模式；Secrets 模式仍使用离线脚本。

页面通过管理认证的 `GET /api/services/tsa` 加载公开证书、日期和签发 CA 范围，不返回密钥或令牌。`POST /api/services/tsa/renew` 可传 `subject`、`notBefore`、`notAfter`、`expectedSerial`；日期需成对提供，`expectedSerial` 防止旧页面覆盖已更新的证书，并保留事务中的配置并发检查。空对象仍沿用当前名称、当前时间起一年。重新签发后备份 D1 并保管 `PKI_MASTER_KEY`；原初始化备份不含新 TSA 私钥，单独恢复它会恢复旧配置。

## 证书签发与 PFX

可以直接在 `/admin` 选择“浏览器生成密钥，下载 CER / PFX”，填写证书名称、用途、有效期和至少 12 字符的 PFX 密码。浏览器生成 RSA-3072 私钥，只把 CSR 发到 Worker；签发完成后本地打包，提供 CER、PEM 证书链和 PFX 下载。私钥和 PFX 密码不上传、不写入 D1 或浏览器持久存储。PFX 包含叶证书私钥、签发 CA 和根证书；使用 AES-256-CBC / PBES2 / PBKDF2-SHA256 加密（私钥 200000 次、证书袋 100000 次），以及 SHA-256 MAC（100000 次），使用新的随机 salt/IV。支持中文等 BMP 字符密码，不支持 Emoji 或空字符。

生成后及时下载并保管 PFX 与密码；刷新页面或再次生成会丢失当前页面中的私钥，服务器无法重新导出它。若打包失败，页面保留本次签发结果和私钥，可重新填写密码并点击“重新打包并下载 PFX”，无需再次签发。选择“粘贴已有 CSR”时，仅返回证书；PFX 需要你原来的私钥，无法从 CER 恢复。证书列表可下载已有证书的 DER 编码 `.cer`；根 CA、签发 CA、TSA、OCSP 也可通过 `/ca/{root,issuer,tsa,ocsp}.cer` 下载。

已通过 Windows 内存导入和 OpenSSL（cryptography）独立读取验证，包括私钥签名匹配、完整链、中文密码、错误密码及篡改检测。Windows 验证使用临时密钥存储，不安装证书或改变系统信任。较旧 Windows 对 AES256-SHA256 PFX 的支持有限，详见 [微软兼容性说明](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/cannot-import-aes256-sha256-encrypted-pfx-certificate)。OpenSSL 互操作测试可设置 `SIGNCERT_TEST_PYTHON` 为装有 `cryptography` 的 Python 路径后运行 `pnpm test`；未设置时跳过该项，Windows 项在其他系统跳过。

在客户端生成密钥，只把 CSR 交给服务：

```powershell
pnpm csr 'My Application' ./client-keys
$adminToken = [System.Net.NetworkCredential]::new('', (Read-Host '输入初始化页面显示的管理令牌' -AsSecureString)).Password
$request = @{ csr = Get-Content client-keys/request.pem -Raw; profile = 'code-signing'; days = 90 } | ConvertTo-Json
$issued = Invoke-RestMethod 'https://pki.example.com/api/certificates' -Method Post -Headers @{ Authorization = "Bearer $adminToken" } -ContentType 'application/json' -Body $request
[IO.File]::WriteAllText((Join-Path $PWD 'client-keys/certificate.pem'), $issued.certificate)
[IO.File]::WriteAllText((Join-Path $PWD 'client-keys/chain.pem'), $issued.chain)
```

也可以在 `/admin` 粘贴 CSR。TLS 请求使用 `profile='server'` 和 `dnsNames=@('app.example.com')`；客户端证书使用 `profile='client'`。管理员负责名称授权，这里没有自动域名所有权验证。

如果本机安装了 OpenSSL，可在客户端打包 PFX（会提示输入导出密码）：

```powershell
openssl pkcs12 -export -inkey client-keys/private.key -in client-keys/certificate.pem -certfile client-keys/chain.pem -out app.pfx
signtool sign /fd SHA256 /tr https://pki.example.com/tsa /td SHA256 /f app.pfx app.exe
signtool verify /pa /v app.exe
```

旧式 `/t` 使用 Base64 SPC/PKCS#7 请求和 SHA-1 CMS 响应；兼容 Windows Base64 的 CRLF 换行与末尾 NUL 字符（例如 256 字节签名对应的 411 字节请求），仍拒绝数据中间的 NUL 与非法 Base64 字符，由 `TSA_LEGACY="true"` 控制；自定义日期路径也适用。新客户端推荐 `/tr` + SHA-256。本地测试覆盖其 CMS 结构、签名与 411 字节请求兼容性；未在本机执行实际 Windows SDK signtool 文件签名测试。解析或服务错误会记录请求字节数与错误原因，不记录请求正文或令牌。

## OCSP、撤销与 CRL

OCSP 支持二进制 POST 和 URL 转义的 Base64 GET。支持 SHA-1（仅用于 CertID 标识）、SHA-256/384/512 CertID；响应签名统一 SHA-256。校验 issuerNameHash 与 issuerKeyHash，未签发或其他 CA 的证书返回 `unknown`；已撤销证书返回原始撤销日期与原因。请求 nonce（1～32 字节）会原样返回。状态是撤销状态，`good` 不意味着证书仍在有效期内，客户端还需验证日期、用途和证书链。

OCSP 与 CRL 的 `nextUpdate` 最多 5 分钟，无 CDN 缓存；客户端仍可能在有效期内复用旧响应，因此撤销传播不保证瞬时完成。CRL 带递增编号和 AKI；不提供 delta CRL，超过 1 万条撤销记录时拒绝生成，需规划分 CA/分区。撤销不支持恢复。

```powershell
Invoke-RestMethod "https://pki.example.com/api/certificates/$($issued.serial)/revoke" -Method Post -Headers @{ Authorization = "Bearer $adminToken" } -ContentType 'application/json' -Body '{"reason":1}'

# 独立验证（需要 OpenSSL）
New-Item -ItemType Directory -Force pki | Out-Null
curl.exe https://pki.example.com/ca/root.pem -o pki/root.pem
curl.exe https://pki.example.com/ca/issuer.pem -o pki/issuer.pem
# client-keys/chain.pem 来自签发响应，包含签发 CA 与根 CA。
Copy-Item client-keys/chain.pem pki/chain.pem
openssl ocsp -issuer pki/issuer.pem -cert client-keys/certificate.pem -url https://pki.example.com/ocsp -CAfile pki/root.pem -verify_other pki/chain.pem -resp_text
curl.exe https://pki.example.com/crl -o current.crl
openssl crl -inform DER -in current.crl -CAfile pki/issuer.pem -verify -text
```

撤销原因：0 未指定、1 密钥泄露、2 CA 泄露、3 从属关系变化、4 被替代、5 停止使用、9 权限撤销、10 AA 泄露。重复撤销保持首次日期和原因，审计仅记录第一次状态变更。

撤销 TSA 会停止时间戳签名，OCSP 仍可报告 TSA 已撤销；撤销 OCSP 响应者会停止 OCSP；撤销签发 CA 会停止签发和状态签名。签发 CA 的状态记录是本系统停用控制，**不等于离线根 CA 签发的撤销声明**。签发 CA 泄露时应由根 CA 的离线流程撤销/替换，并在私有客户端移除旧 CA 信任；当前不生成根 CA CRL。

## 时间戳独立验证

```powershell
openssl ts -query -data app.exe -sha256 -cert -out request.tsq
curl.exe -H 'Content-Type: application/timestamp-query' --data-binary '@request.tsq' https://pki.example.com/tsa -o response.tsr
openssl ts -reply -in response.tsr -text
openssl ts -verify -in response.tsr -queryfile request.tsq -CAfile pki/root.pem -untrusted pki/chain.pem
```

摘要算法不支持或摘要长度错误返回协议错误，而不会回退成另一个算法。RFC 3161 默认接受 SHA-256/384/512；签名摘要始终 SHA-256。仅 `certReq=true` 时内嵌 TSA 与签发 CA 证书。成功返回前必须完成 D1 时间戳记录，数据库不可用时不会发出成功响应。

## 续期与运维

`/health` 验证服务证书链、私钥匹配、有效期、D1 可用性和服务证书登记状态。返回 ready 表示当前可工作，不代表已经公开受信或时间源通过审计。

TSA/OCSP 默认为 1 年，签发 CA 5 年，根 CA 10 年。Web 初始化模式可在 `/admin` 使用管理令牌点击 TSA/OCSP 续签；Worker 生成新服务密钥，以在线签发 CA 签发，并事务更新加密配置与登记记录。旧服务证书记录保留，访问令牌和根证书保持不变。并发续签发生冲突时会拒绝其中一次，请刷新后重试。生产 Worker 的 CPU 额度需容纳 RSA-3072 密钥生成；本地验证不能代替生产额度检查。

Web 模式续签后，初始化时下载的备份仍包含原服务密钥；保留它用于根私钥恢复，同时备份当前 D1 和原 `PKI_MASTER_KEY`，才能恢复最新在线配置、签发和撤销状态。不要用旧备份覆盖续签后的系统。

离线 Secrets 模式继续使用本地保管的在线签发 CA 密钥生成新的服务证书：

```powershell
pnpm renew-service tsa ./renewal-tsa https://pki.example.com
pnpm exec wrangler d1 execute signcert --remote --file renewal-tsa/seed.sql
pnpm exec wrangler secret bulk renewal-tsa/secrets.json
# OCSP 同理，用 ocsp 参数。新 Secret 上传后检查 /health。
```

先登记新证书，再替换 Secret。保留旧服务证书登记和撤销记录，用于历史状态查询；轮换后自行更新 `pki/TSA_CERT`、`pki/TSA_KEY`（或 OCSP 对应文件）、本地 `.dev.vars` 和备份，避免后续把旧密钥重新部署。签发 CA 和根 CA 轮换需要离线根流程、客户端信任分发和旧服务地址保留；当前单实例仅响应一个签发 CA，应为新 CA 部署独立实例并保留旧实例处理历史 OCSP/CRL。

D1 记录是必要状态，请做备份与恢复演练。时间戳记录随请求增长，只有摘要没有原文；保留期由你决定，批量清理前导出需要保留的审计证据。Web 模式分别备份加密根备份、备份密码、主密钥和 D1；仅恢复初始化备份不会找回历史签发、撤销和审计记录。Secrets 模式分别备份 Secrets 与 D1。没有自动备份、自动证书轮换、时间校准、额度/用户计费或无人值守部署。

## API

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/` | 服务能力 |
| GET | `/health` | 就绪检查 |
| GET | `/admin` | 管理页面 |
| GET | `/setup`、`/setup.js` | 网页初始化与浏览器脚本 |
| GET | `/api/setup/status` | 初始化状态，不返回密钥 |
| POST | `/api/setup` | 首次初始化；Bearer 主密钥认证 |
| GET | `/api/services/tsa` | 当前 TSA 公开证书与日期配置；管理认证 |
| POST | `/api/services/{tsa,ocsp}/renew` | Web 模式服务续签；TSA 支持名称、启止时间与旧序列号校验；管理认证 |
| POST | `/`、`/tsa` | RFC 3161 DER 或 Authenticode Base64 |
| POST | `/{datetime}`、`/tsa/{datetime}` | 自定义 UTC 时间；开关+独立令牌 |
| POST | `/ocsp` | DER OCSP 请求 |
| GET | `/ocsp/{urlencoded-base64}` | OCSP GET 请求 |
| GET | `/crl` | 签发 CA 的 DER CRL |
| GET | `/ca/{root,issuer,tsa,ocsp}.{pem,der,cer}` | 公共证书；CER 为 DER 下载 |
| GET/POST | `/api/certificates` | 分页列表 / CSR 签发；Bearer 管理认证 |
| GET | `/api/certificates/{serial}` | 证书详情；管理认证 |
| POST | `/api/certificates/{serial}/revoke` | 永久撤销；管理认证 |
| GET | `/api/audit` | 最近 200 条审计；管理认证 |

管理 UI 不存储令牌，证书与审计文本使用 `textContent` 展示；设置 CSP 和无缓存。请求体最多 64 KiB；OCSP 每次最多 20 张证书。

## 验证与参考

管理页面返回 `Unauthorized` 时，可在项目目录运行 `powershell -NoProfile -File .\scripts\diagnose-auth.ps1`，按提示输入原 `PKI_MASTER_KEY` 与报错的管理令牌。脚本只读远程 D1，在本机解密并核对令牌，只输出匹配结果，不打印或保存密钥，不向线上签名接口发送令牌。请勿把密钥作为命令行参数或发给他人。`PKI_MASTER_KEY`、管理令牌和自定义时间戳令牌是三个不同的值。

`pnpm check` 做类型检查；`pnpm test` 先执行 Wrangler dry-run，再在实际 workerd/Miniflare 和本地 D1 中运行集成测试。覆盖网页初始化认证与并发保护、加密备份篡改检测、根私钥不上传、加密配置重启恢复、主密钥错误、服务续签及并发冲突，以及 CSR 签发、认证、SAN、CMS/ESSCertIDv2、nonce、协议错误、自定义日期和审计、OCSP GET/POST/签名/状态、撤销幂等性、CRL 签名和服务撤销。证书额外由 Node/OpenSSL 的 X509Certificate 独立验证。

参考：[FakeSign TSWorker](https://github.com/PIKACHUIM/FakeSign/tree/main/TSWorker)、[RFC 3161](https://www.rfc-editor.org/rfc/rfc3161)、[RFC 5816](https://www.rfc-editor.org/rfc/rfc5816)、[RFC 6960](https://www.rfc-editor.org/rfc/rfc6960)、[Workers WebCrypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)、[Worker Secrets](https://developers.cloudflare.com/workers/configuration/secrets/)、[PKI.js](https://pkijs.org/docs/)。上游实现未直接复制；该项目是接口与架构上的整合扩展。
