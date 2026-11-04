# OhMyKei：CTAP 2.3 实现范围与方向

依据：CTAP 2.3 PS（2026-02-26）全文中与 USB HID 漫游认证器相关的章节（§5–§9、§11.1–11.2、§12）、本地 FIDO 一致性测试工具 v1.9.3.1 的 `ctap2.3-conformance-module` 测试源码，以及当前 [ROADMAP.md](ROADMAP.md) 的定位（纯 FIDO2、单 HID、无 U2F、无生物识别、P-256 + Ed25519）。

> [!IMPORTANT]
> **一致性测试要选“非 featureful”配置。** 测试工具里的 `profile_featureful` 是自愿勾选的。勾上之后，它会强制要求 PIN 协议 1+2、credBlob、minPinLength、authenticatorConfig + toggleAlwaysUv、thirdPartyPayment、hmac-secret-mc，以及 largeBlob 或 largeBlobKey+0x0C 二选一。这和“不做 largeBlobs”的定位冲突。不勾的话，以上每一项都是“getInfo 声明了才测，没声明就 skip”。所以目标是：**通过默认配置下的完整 CTAP 2.3 测试**。

---

2026-11-04 同步：已完成 DER/descriptor/格式偏好字段修复，精简无用公钥计算和枚举重复逻辑；随后清理 CTAP/PIN 的重复检查、无用状态与重复 PUAT 查询接口，扩展 HMAC 派生结果改为局部使用后清理。验证记录见 [audit-plan.md](audit-plan.md#55-2026-11-04-ctappin-过度防御清理)。当前为 dev 阶段，OTP 熔丝和 boot 刷写锁定不在本轮实现范围。

## 1. 范围总表

2026-11-04 自动化补充：已有 Colima 原生核心 + UHID 路径，可在无真机条件下运行
九项核心回归和十项独立客户端端到端测试；Linux UBSan 发现的可选用户字段空指针
零长度拷贝已修复。硬件时序和官方完整套件结果单独记录，见 [automation.md](automation.md)。
官方 v1.9.3.1 的 GetInfo/PIN 协商最小集已取得 5 通过、2 能力不适用跳过、0 失败；
首轮完整 CTAP 2.3 清单取得 183 通过、118 官方跳过、25 失败；4 个元数据错误
已修正，再次全量验收为 187 通过、118 官方跳过、21 失败，无漏跑。协议用例待定位。
官方入口默认全量，支持冒烟与定向筛选；报告包含
完整性判定、重试和环境标识。该结果不代表一致性认证通过。

| 类别 | 项目 | 决定 |
|---|---|---|
| 传输 | CTAPHID：INIT / PING / CBOR / CANCEL / ERROR / KEEPALIVE | **做** |
| | CTAPHID_WINK | **做**（用 LED，成本几乎为零） |
| | CTAPHID_MSG（U2F） | **不做**：INIT 能力位设 `NMSG`，收到 MSG 回 `ERR_INVALID_CMD` |
| | CTAPHID_LOCK | 不做 |
| 命令 | MakeCredential 0x01、GetAssertion 0x02、GetInfo 0x04、ClientPIN 0x06、Reset 0x07、GetNextAssertion 0x08、CredentialManagement 0x0A、Selection 0x0B | **做** |
| | authenticatorConfig 0x0D | **第二批**（和 minPinLength 绑定，见 §4） |
| | BioEnrollment 0x09、LargeBlobs 0x0C、原型命令 0x40/0x41 | 不做 |
| PIN/UV | PIN/UV Auth 协议 **2 和 1** | **都做**（顺序 `[2, 1]`） |
| | getPinToken 0x05（已被取代） | **做**（§1.1：支持 clientPin 且声明 FIDO_2_0 时是 MUST） |
| | getPinUvAuthTokenUsingPinWithPermissions 0x09 | **做** |
| | UsingUv 0x06 / getUVRetries 0x07 | 不做（没有内置 UV）→ `INVALID_SUBCOMMAND` |
| | persistentPinUvAuthToken / `pcmr` / encIdentifier / encCredStoreState | **后补**（存储里先留好字段） |
| 扩展 | hmac-secret | **做**（§9：MUST） |
| | credProtect | **做**（§9：MUST） |
| | hmac-secret-mc | **做**（hmac-secret 做完后几乎是复用） |
| | credBlob | 后补（只支持 rk，成本低） |
| | minPinLength | 第二批（必须连同 authenticatorConfig/setMinPINLength 一起做，§9.7） |
| | largeBlobKey / largeBlob / thirdPartyPayment / pinComplexityPolicy | 不做 |
| 特性 | makeCredUvNotRqd = true | **做**（SHOULD；对 SSH-SK 很关键） |
| | alwaysUv | 第二批（和 authenticatorConfig 一起） |
| | 企业认证 ep、longTouchForReset、certifications、BLE/NFC/Hybrid/JSON 消息 | 不做 |

---

## 2. getInfo 的目标形态

getInfo 是“声明即承诺”：测试工具和平台完全根据它决定发什么请求、跑哪些测试。**没实现的东西一律不出现**（key 不出现，或者 option 不出现）。

```text
versions        ["FIDO_2_0", "FIDO_2_1", "FIDO_2_3"]   // 禁止出现 "FIDO_2_2"；不声明 U2F_V2 和 FIDO_2_1_PRE
extensions      ["credProtect", "hmac-secret", "hmac-secret-mc"]
aaguid          固定的型号 UUID（同型号一致，Reset 不变）
options         rk:true, up:true, plat:false,
                clientPin:<是否已设 PIN>, pinUvAuthToken:true,
                credMgmt:true, makeCredUvNotRqd:true
                // 不出现 uv / bioEnroll / largeBlobs / ep / authnrCfg（第二批再加）
maxMsgSize      选大一点（RAM 足够，比如 ≥2048）
pinUvAuthProtocols [2, 1]
maxCredentialCountInList / maxCredentialIdLength   按实际凭据 ID 格式给出
transports      ["usb"]
algorithms      [{alg:-7, type:"public-key"}, {alg:-8, type:"public-key"}]
minPINLength    4
firmwareVersion 每次发布必须递增
remainingDiscoverableCredentials  按“最大字段尺寸”保守估算
```

为什么同时声明 2.0 和 2.1：平台按版本字符串打开对应特性。声明 FIDO_2_0 会带出 getPinToken、`uv` 选项兼容、零长度 pinUvAuthParam 等旧行为义务，这些都要做。

---

## 3. 必做部分的方向

### 3.1 CTAPHID 传输与并发模型（最先定下来的架构决策）

- **在等用户按键时，USB 必须照常处理。** 等待触摸（UP）期间要做到：至少每 100 ms 发一次 KEEPALIVE（`UPNEEDED`）；当前 CID 的 CANCEL 让这次请求返回 `CTAP2_ERR_KEEPALIVE_CANCEL`；同一 CID 的 INIT 中止这次事务；其他 CID 的新请求立即回 `ERR_CHANNEL_BUSY`；广播 CID 的 INIT 仍然要能分配新通道。做法：在等待循环里轮询 USB 栈和 HID 收包（协作式），或者把协议处理放进独立任务。**不能**写成一个阻塞的 `wait_button()`。
- 报文重组：每次事务只用一个请求缓冲区；检查 SEQ 是否严格递增、BCNT 是否越界、有没有游离的续包（直接忽略）；事务超时后回到空闲状态。CANCEL 本身永远不回复。
- 这一层和 CBOR 层一样，要能在 host 端测试和 fuzz（ROADMAP 已有要求）。
- §11.1 要求：FIDO 状态不能通过非 FIDO 接口观察或修改。当前固件已移除 CDC 调试口，只保留单一 FIDO HID；后续不得重新引入可读取认证器状态的调试接口。

### 3.2 CBOR

- 输出必须是 CTAP2 规范编码：整数最短编码、定长、map 的 key 按“先比类型，再比长度，再按字节序”排序。
- 输入：拒绝非规范编码和重复 key（`INVALID_CBOR`），嵌套深度至少支持 4 层，**忽略不认识的 key**，必需字段缺失或类型不对返回 `CBOR_UNEXPECTED_TYPE` 或 `MISSING_PARAMETER`。
- 方向：自己写一个小而严格的解析器和编码器（只需要 uint/nint/bytes/text/array/map/bool），把它作为第一个 libFuzzer 目标。

### 3.3 凭据模型（影响面最大的设计）

- **非驻留凭据**：凭据 ID 自包含，用设备主密钥做 AEAD 包装（或者复用 AES-256-CBC + HMAC 做先加密后 MAC）。内容包括版本号、标志位（rk、credProtect 级别）、随机 nonce、私钥种子；**rpIdHash 作为 AAD 绑定**，换一个 RP 必须解不开。Reset 时轮换主密钥，旧凭据全部失效。
- **驻留凭据**：完整记录存在 flash 里（rpId、user.id/name/displayName、私钥种子、credProtect、创建序号、可选的 credBlob）。规范 §6.1.3 规定：**rk 被删除或覆盖后，它的凭据 ID 不能再被认出来，即使 ID 本身是自包含的。** 所以 ID 里带 rk 标志位，验证时必须再去 flash 确认记录还在。
- 同一个 rp.id + user.id 再次创建时覆盖旧记录。GetAssertion 里多个凭据按创建时间倒序排，所以要存单调的创建序号。
- 两种凭据可以共用同一种 ID 格式，这样查找路径统一。

### 3.4 MakeCredential / GetAssertion / GetNextAssertion

- **严格按规范 §6.1.2 和 §6.2.2 的步骤顺序实现**，错误码和副作用（消耗 UP、清理权限）都取决于顺序。最容易漏的几项：
  - **零长度 pinUvAuthParam**：先等一次触摸，然后返回 `PIN_NOT_SET` 或 `PIN_INVALID`（CTAP 2.0 浏览器靠这个选认证器）。
  - `up:false` 在 MakeCredential 里返回 `INVALID_OPTION`；`rk` 出现在 GetAssertion 里返回 `UNSUPPORTED_OPTION`；`uv:true` 返回 `INVALID_OPTION`（没有内置 UV）。
  - 设了 PIN 之后：rk 必须带 PUAT（`PUAT_REQUIRED`）；非 rk 在 makeCredUvNotRqd 下可以不带。
  - excludeList 命中时，**先等一次触摸再**返回 `CREDENTIAL_EXCLUDED`；credProtect=3 且没有 uv 时，就当作没命中。
  - 每次真正收集到 UP 后，执行 clearUserPresentFlag / clearUserVerifiedFlag / 清除除 lbw 以外的权限。也就是说 PUAT 用一次就失去 mc/ga 权限。
  - `up:false` 的预检（pre-flight）请求不等触摸，flags 里 up=0。
  - 没有 uv 时，返回的 user 里不能带 name/displayName。
- 没有显示屏，所以多凭据时返回 `numberOfCredentials`，用 GetNextAssertion 迭代：状态带 30 s 计时器，期间出现任何其他命令就丢弃状态。
- `pubKeyCredParams` 要整个遍历校验，选第一个支持的算法；`attestationFormatsPreference (0x0B)` 如果只有 `"none"`，就省略认证声明。
- ES256 的 packed 自证明和断言签名使用 ASN.1 DER，Ed25519 保持 64 字节。断言仅校验算法和 P-256 标量范围，不为校验额外派生未使用的公钥。

### 3.5 签名计数器

- 测试工具会验证**连续三次 assertion 的计数器严格递增**。用一个全局单调计数器就够了（逐凭据计数没有必要）。
- 关键是掉电后**绝不能回退或重复**，同时不能每次签名都擦 flash。方向：在 flash 上做追加写日志（每次写几个字节，一个扇区写满再换），或者“预留 N 个值先落盘，启动后从预留上界继续”。

### 3.6 ClientPIN

- 当前实现中两个协议共用 ECDH 协商密钥和一个 32 字节 PUAT，以及权限、RP 绑定和使用计时状态。初始 30 s 内必须使用，之后每次成功授权刷新 30 s 空闲窗口；自签发起的 10 min 绝对期限不刷新。有效性判据仅在真实授权路径维护。
- COSE 类型与坐标长度在解析层检查，曲线点合法性由 ECDH 原语统一检查。PIN 解密前检查密文形状和输出容量，调用者依赖其成功契约，不再复查固定明文长度。
- 子命令：getPINRetries（带 `powerCycleState`）、getKeyAgreement、setPIN、changePIN、getPinToken、getPinUvAuthTokenUsingPinWithPermissions。permissions 先按 getInfo 校验，返回 `UNAUTHORIZED_PERMISSION`：本设备上 `be`/`lbw`/`acfg`/`pcmr` 一律拒绝，只放行 mc/ga/cm。
- **安全行为**：`pinRetries`（最多 8 次）**先持久化减一，再比较**；每次上电连续错 3 次返回 `PIN_AUTH_BLOCKED`（计数只放 RAM）；比对失败时调用 `regenerate()`；改 PIN 后重置所有 PUAT。PIN 保存 `LEFT(SHA-256(pin),16)`，保护强度要和私钥相同。
- 这几条要在 host 测试和 fuzz 里覆盖（ROADMAP 第 3 阶段的“掉电一致性”主要就落在这里和计数器上）。

### 3.7 CredentialManagement

- 子命令：getCredsMetadata、enumerateRPsBegin/GetNextRP、enumerateCredentialsBegin/GetNext、deleteCredential、updateUserInformation。
- 校验：`cm` 权限；枚举类命令要求 PUAT **没有**绑定 RP ID；删除和更新允许 RP ID 匹配的 PUAT（`ssh-keygen -K` 这类场景会用到）。
- 存储的 rpId 可以按 §6.8.7 截断后用于展示，**比较时必须用完整值或 rpIdHash**。
- 各子命令按规范返回相应的 rp、user、credentialID、publicKey、credProtect。credentialID 在枚举响应及删除/更新参数中都是包含 `id`、`type` 的 descriptor map。
- 枚举首条与续页共用凭据响应函数，仅首条含 `totalCredentials`；RP 哈希在入口校验后传给内部 helper。枚举状态是有状态命令，PUAT 过期后要丢弃。

### 3.8 Reset / Selection

- Reset：只在上电后 10 s 内接受，超时返回 `NOT_ALLOWED`；需要触摸确认。清除内容：主密钥、全部 rk、PIN、重试计数、配置项；同时重新生成凭据库状态随机数（将来做 encIdentifier 时可以直接用）。型号 AAGUID 是认证器型号标识，**Reset 不重生**。
- Selection：等一次触摸，返回 OK、`OPERATION_DENIED` 或 `USER_ACTION_TIMEOUT`。用户操作超时 ≥10 s，建议 30 s。

### 3.9 扩展

- **hmac-secret**：CredRandomWithUV 和 WithoutUV **不存储，而是派生**（HKDF(主密钥, 凭据内部秘密 ‖ uv 标志)）。这样非驻留凭据也能支持（§12.7 规定两类凭据都 MUST 支持）。`pinUvAuthProtocol` 缺省时按协议 1 处理，这也是必须实现协议 1 的直接原因：旧客户端会这么发。`up:false` 时返回 `UNSUPPORTED_OPTION`；salt 长度只接受 32 或 64 字节。**用不用 PIN 会得到不同的输出**，这点要写进用户文档（age / SSH 场景）。
- **hmac-secret-mc**：在 MakeCredential 里用相同的处理逻辑直接输出（WebAuthn PRF 在创建凭据时就能求值）；没带 hmac-secret 时返回 `MISSING_PARAMETER`。
- **credProtect**：值随凭据持久化（非驻留凭据存在 ID 的标志位里）；默认值 1；不能主动返回没被请求的输出。它影响三个地方：GetAssertion 过滤、excludeList、credMgmt 返回值。

### 3.10 认证声明（attestation）

开源固件没法保护批量认证私钥（每台设备自签名证书也违反批量 ≥10 万台的隐私要求）。方向是用 **`packed` 自认证**，不带 x5c，用凭据私钥签名，元数据里 `attestationTypes` 写 `["basic_surrogate"]`（测试工具认可这个组合）。请求 `"none"` 时返回 `fmt:"none"`。不声明 `attestationFormats`。

---

## 4. 第二批（基础功能通过测试后再做）

- **authenticatorConfig 0x0D + `acfg` 权限 + toggleAlwaysUv + setMinPINLength + minPinLength 扩展**，作为一个整体一起做。依据：§9.7 规定声明了 minPinLength 就必须支持 setMinPINLength，而它依赖 authenticatorConfig。alwaysUv 对开发者有实际价值（强制所有 SSH/WebAuthn 操作都要 PIN）。注意它和 makeCredUvNotRqd 的联动，以及“设备还没受保护”时的分支（§6.11、§7.2）。ROADMAP 第 2 阶段把 minPinLength 单独列为“核心扩展”，应该改成这个组合。
- **credBlob**：只支持 rk，`maxCredBlobLength` = 32。
- **persistentPinUvAuthToken + `pcmr` + `perCredMgmtRO` + encIdentifier / encCredStoreState**：让平台缓存凭据列表时不用每次都输 PIN。需要的设备标识、凭据库状态随机数在 §3.8 里已经在维护。

## 5. 明确不做，及理由

- **CTAP1/U2F**：规范 §10 是 SHOULD，并提示“不适合面向大众销售”。但现代浏览器和 libfido2/OpenSSH 都走 CTAP2，旧 U2F 凭据的 appid 场景对一台全新的钥匙不存在；CTAP 2.3 测试模块也允许 `NMSG`。保持现有决定。
- **largeBlobs / largeBlobKey / largeBlob**：只有 featureful 配置强制要求，RP 侧几乎没人用，还要管 ≥1 KB 的存储、垃圾回收和 `lbw` 权限语义。
- **BioEnrollment / 内置 UV / `uv` 选项**：没有硬件。注意：**按键是 UP，不是 UV**，绝不能因为按了键就把 uv 位置 1。
- **企业认证、certifications、thirdPartyPayment、pinComplexityPolicy、longTouchForReset、BLE/NFC/Hybrid/JSON 消息**：不在定位范围内，或者需要不存在的硬件和厂商基础设施。

## 6. 已并入 ROADMAP 的修订记录

以下结论已经写入 [ROADMAP.md](ROADMAP.md)，保留在此作为决策依据：

1. PIN/UV 实现 **协议 2 和 1 + getPinToken**。
2. **hmac-secret-mc** 属于核心扩展；minPinLength 移到第二批，和 authenticatorConfig 绑定。
3. 第 1 阶段包含等待触摸期间不阻塞 USB 的并发模型（§3.1）和不会回退的签名计数器（§3.5）。
4. 一致性目标为 **CTAP 2.3 模块，默认（非 featureful）配置**。
5. RP2350 在 BOOTSEL 模式下可用 picotool 直接读出 flash；主密钥和 PIN 哈希明文存放没有物理保护，OTP/安全启动仍属于后续加固阶段。
