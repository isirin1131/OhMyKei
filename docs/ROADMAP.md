# OhMyKei 方向与路线图（v1）

> 依据：`ResearchDocs/01~03`。状态：**方向已定**，仅剩密码学依赖待议（见 §7）。

---

## 0. 一句话定位

**一个 MIT 许可、C11 从零编写、跑在 RP2350-Zero-CM 上的 YubiKey 替代品：协议兼容做满，安全只做“性价比拐点”以内的事，并且没有厂商——用户自己签固件、自己持有根密钥、自己托管所有服务端。**

---

## 1. 三条底线

| 底线 | 具体做法 |
| :--- | :--- |
| **MIT 洁净室** | 只参照**规范**（CTAP 2.1/2.2、U2F、OpenPGP Card 3.4、NIST SP 800-73-4、YKOATH、Yubico OTP、CCID 1.1、ISO 7816-4）编写。canokey（Apache-2.0）和 RS-Key（**AGPL**）只用来理解架构、行为与踩坑点，**不复制、不逐行翻译**（Rust→C 逐行翻译仍可能构成衍生作品）。在 `docs/CLEAN_ROOM.md` 记录每个模块参照的规范章节。 |
| **依赖许可白名单** | 只接受 MIT / BSD / ISC / CC0 许可，**不引入 Apache-2.0**。当前清单：pico-sdk（BSD-3）、TinyUSB（MIT）、LittleFS（BSD-3）、BearSSL（MIT）、Monocypher（BSD-2 OR CC0）。随二进制附带 `THIRD_PARTY_NOTICES`。 |
| **用户即厂商** | 不内置任何厂商签名密钥、不依赖网页控制台或云端。secure boot 的 secp256k1 私钥由用户自己生成；attestation 证书可由用户自己的 CA 签发；Yubico OTP 由用户自建验证服务器。 |

---

## 2. 安全甜点：做什么 / 不做什么

威胁模型以 DOC-03 §三为准：**防远程、防钓鱼、防丢失后的普通提取；不防实验室级物理攻击。**

### ✅ 做（便宜且收益高）

1. **Secure boot + 防回滚版本号**：用户自己的 secp256k1 密钥签名（`picotool seal`），OTP 中写入 bootkey 哈希。这是分区表围栏真正生效的前提。
2. **分区表围栏**：数据分区设置 `bootloader: ""`，挡住 BOOTSEL 模式下的 `picotool save --all` 整片导出。
3. **每设备 OTP 主密钥（MKEK）**：首次初始化时在设备上用 TRNG 生成，写入 OTP 后对该页 soft-lock；按 **密钥 + 反码** 成对存放（chaff），缓解 PVC 读取。MKEK 不出片。
4. **数据静态加密**：每条记录用 AEAD（AES-GCM 或 ChaCha20-Poly1305）加密，密钥 = HKDF(MKEK, 用途标签)。只在记录层加密，文件系统本身不加密。
5. **⭐ OTP 单调 PIN 失败计数器（主打差异点，需先做 PoC）**：每次校验 PIN **之前**先烧掉 1 个 OTP bit，校验成功后在 Flash 里记下当前计数快照。剩余次数 = 上限 −（OTP 计数 − 快照）。回滚 Flash 只能让快照变旧，剩余次数只会变少，因此**整片回滚和拆焊 Flash 回放都绕不过 PIN 重试上限**——这正是 Token2 advisory 描述的攻击路径。拿出 2 个 OTP 页大约能计 3000 次失败，按寿命算够用；用完后退回 Flash 计数器并给出提示。
6. **关闭调试、启用 glitch detector**：只需设置 OTP 标志位，量产阶段一次完成。
7. **软件层面的基本功**：常数时间比较、RSA 盲化、敏感缓冲区及时清零、栈金丝雀、看门狗。
8. **PIN 不存明文**：OpenPGP 实现 KDF-DO（canokey 是明文 + `memcmp`）；CTAP 本身只存 PIN 哈希。

### ❌ 不做（收益低或芯片做不到）

| 项 | 理由 |
| :--- | :--- |
| TrustZone Non-Secure 隔离 | SDK 没有 `arm-ns` 平台，需要自写启动代码和 veneer；攻击者模型是同一颗裸片，隔离收益很小。RS-Key 也没做。 |
| Encrypted boot | 固件本身开源，秘密在数据区不在代码里；而且只能解密到 SRAM，会挤占内存。 |
| 软件 DPA 掩码、抗故障注入的冗余计算 | 物理攻击本来就在威胁模型之外，做了也挡不住专业设备。 |
| NFC | 板上没有 NFC 硬件。 |
| WebUSB 网页控制台 | 和“干净、自托管”的定位冲突，管理统一走 CLI。 |
| FIDO 的 PQC（ML-DSA） | **已确认砍掉。** 浏览器和 RP 都不支持；ML-DSA-87 需要约 123 KiB 栈。 |
| 国密 SM2/SM3/SM4 | **已确认砍掉。** 目标客户端（浏览器、gpg、ssh、ykman）都不用。 |
| 冒用 Yubico VID/PID | **已确认不做。** 只做协议层兼容（YKOATH / PIV / OpenPGP / OTP）。**代价**：据 DOC-03，ykman 和 Yubico Authenticator 依赖 Yubico 的 VID/PID 或 reader 名来识别设备，大概率认不出我们；OATH 和 OTP 的管理由 `omk` CLI 承担。gpg、OpenSC、ssh、浏览器不受影响。 |
| A/B 双固件槽 | bootrom 的 BOOTSEL 永远可以重刷，不会变砖；省下的空间留给数据区。 |
| 硬件单调计数器 / 防拆网格 | MCU 本身就没有，第 5 条已用 OTP 做了替代。 |

---

## 3. 功能范围（分档）

| 档 | 功能 |
| :--- | :--- |
| **P0：MVP** | CTAPHID；CTAP 2.1（getInfo / makeCredential / getAssertion / getNextAssertion / clientPIN 协议 v1+v2 + token permissions / reset / selection / credentialManagement）；U2F；ES256 + EdDSA；驻留凭据（目标 ≥256，只受存储限制）；`credProtect`；`hmac-secret`；BOOTSEL 作为 UP；LED 状态指示 |
| **P1：日常主力** | CCID；OATH（YKOATH，兼容 Yubico Authenticator）；OpenPGP 3.4 的 ECC 部分（Ed25519 / X25519 / P-256 / P-384，UIF）；`largeBlobs`、`minPinLength`、`alwaysUv`；种子备份/恢复（BIP-39） |
| **P2：补全** | OpenPGP RSA-2048/3072/4096（密钥生成放在 Core 1）；PIV（9A/9C/9D/9E + retired 槽，ECC 与 RSA-2048，AES 管理密钥）；ES384 / ES512（BearSSL 原生支持 P-521，不额外增加成本）/ ES256K；键盘 HID：Yubico OTP（配合自建 ykval）/ HOTP / 静态密码；用户自建 CA 签发的 attestation 证书（设备只存储、不生成，见约束 C） |
| **砍掉** | 见 §2 的“不做”清单 |

**非驻留凭据的设计**：credential ID = `ver ‖ nonce ‖ MAC(K_mac, rpIdHash ‖ nonce ‖ alg ‖ flags)`，私钥 = HKDF(seed, nonce ‖ rpIdHash)。这样备份 seed 就等于备份了全部非驻留凭据，主/备两把 key 可以共享同一个 seed。

---

## 4. 架构与技术选型

```
src/
  platform/   RP2350 专属：BOOTSEL、WS2812(PIO)、TRNG、flash(flash_safe_execute)、OTP、USB 描述符
  transport/  ctaphid.c  ccid.c  kbd_hid.c         ← TinyUSB 回调只做搬运
  core/       cbor.c  tlv.c  apdu.c  storage.c(AEAD+LFS)  crypto_hal.h + crypto_*.c
  apps/       fido2/  u2f/  oath/  openpgp/  piv/  otp/  mgmt/
host/         同一份 core+apps 在 macOS 本机编译 → 单元测试 + libFuzzer + ASan/UBSan
tools/omk/    Python CLI（MIT）：初始化、OTP 熔丝、签名封包、备份、配置
```

- **平台无关**：`core/` 和 `apps/` 不引用 pico-sdk，必须能在 host 上编译。在 C 语言下，这是唯一能把 fuzz 做扎实的办法。
- **USB**：TinyUSB 提供复合设备。TinyUSB 主线**没有 CCID device class**，要通过 `usbd_app_driver_get_cb` 自己写一个。
- **密码学**：BearSSL（MIT）+ Monocypher（BSD-2 OR CC0），不使用堆内存，所有调用都经过 `crypto_hal.h`，详见约束 C。
- **CBOR**：自己写一个严格的 canonical 子集解析器，限制深度和长度，作为第一个 fuzz 目标。
- **存储**：LittleFS 存放加密记录；另外划一块小环形区专门写 FIDO 签名计数器，避免 LFS 元数据被频繁擦写。
- **并发**：Core 0 负责主循环（`tud_task` + 协议处理），Core 1 只承担长任务（RSA 密钥生成/运算）。Core 1 启动时必须调用 `flash_safe_execute_core_init()`。
- **BOOTSEL 采样**：放进 `flash_safe_execute()` 回调，使用 `SIO_GPIO_HI_IN_QSPI_CSN_BITS`（bit 27）。只在等待 UP 时以 10–20 ms 周期采样。
- **语言**：C17（`-std=c17 -Wall -Wextra -Werror`），host 和固件使用同一套警告集。

### 架构硬约束 A：非阻塞（从第一行代码起）

**任何协议处理函数都不允许阻塞等待**，包括等按键、等 Core 1、在循环里 sleep。canokey 的 `wait_for_user_presence()` 会在内部自转 30 秒，这种写法禁止。

```c
typedef enum { JOB_DONE, JOB_PENDING, JOB_ERROR } job_status_t;

typedef struct job {
    job_status_t (*step)(struct job *j, uint32_t now_ms); // 每次只做有界的一小步
    void (*cancel)(struct job *j);                         // CTAPHID CANCEL、CCID abort、USB 复位时调用
    uint8_t kind;                                          // UP_WAIT / CORE1_CRYPTO / ...
    /* 应用私有状态 */
} job_t;
```

- 主循环：`tud_task()` → `transport_tick(now)` → `job_step(now)`。
- 只要有 job 处于 `JOB_PENDING`，传输层就自动按周期发送保活：CTAPHID 约每 100 ms 发 KEEPALIVE（`UPNEEDED` 或 `PROCESSING`），CCID 发 Time Extension。应用层不感知这件事。
- UP 等待是一个 job，每一步采样一次 BOOTSEL，超时后返回 `CTAP2_ERR_USER_ACTION_TIMEOUT`。
- Core 1 的运算也是一个 job：`step()` 只检查 FIFO 里有没有结果；`cancel()` 置位中止标志，由 Core 1 在迭代间隙检查。
- 同一时刻只允许一个 job，第二个请求直接返回 BUSY（CTAPHID 本身就是这个语义）。
- host 端用假时钟驱动 job，可以确定性地测试超时、取消和并发 BUSY。
- 已知阻塞源：Flash 擦除会暂停 XIP。规则是记录写入不放在 UP 等待中途；擦除按 4 KB 粒度切分。最坏情况的耗时要在 M1 实测。

### 架构硬约束 B：OTP HAL + Mock

```c
// platform/otp_hal.h —— 应用层和存储层只通过这个接口访问 OTP
int  otp_read_ecc(uint16_t row, uint16_t *out, size_t n);
int  otp_write_ecc(uint16_t row, const uint16_t *in, size_t n);
int  otp_read_raw(uint16_t row, uint32_t *out, size_t n);   // 24-bit
int  otp_write_raw(uint16_t row, const uint32_t *in, size_t n);
int  otp_lock_page(uint8_t page, otp_lock_t mode);
```

| 后端 | 用途 | 默认 |
| :--- | :--- | :--- |
| `otp_mock_ram` | host 测试 | host 默认 |
| `otp_mock_flash` | 开发板调试：用数据区里一个专用扇区模拟，重启后不丢 | **固件默认** |
| `otp_real` | 真 OTP | 只有 `-DOMK_OTP_REAL=ON` 才会编译进来 |

- **Mock 必须如实模拟 OTP 的物理语义**：bit 只能从 0 写成 1；ECC 行重复写入会报错；锁页后读写都被拒绝；未初始化的行读出为 0。否则 mock 测试会给出虚假的信心。
- **真 OTP 的三重闸门**：编译开关 + 固件运行时确认（`omk` 发送带设备序列号的确认 APDU）+ 每次写入前先回读校验目标行为空。
- 烧真 OTP 的第一个对象只能是**一块专用于牺牲的测试板**，并且必须先在 mock 上通过 PIN 计数器的全部测试。

### 架构硬约束 C：密码学栈（纯 MIT/BSD/CC0、零 malloc、常数时间）

**分工**

| 库 | 只引入的部分 | 负责 |
| :--- | :--- | :--- |
| **BearSSL**（MIT，固定到某个 commit 并 vendor 进仓库） | `src/int` `src/ec` `src/rsa` `src/symcipher` `src/hash` `src/mac` `src/kdf` `src/rand`，不要 TLS / X.509 层 | RSA-2048/3072/4096（`br_rsa_i31_keygen`、原始私钥运算、PKCS#1 v1.5、PSS、OAEP）；P-256 / P-384 / P-521 ECDSA（RFC 6979）与 ECDH；AES-GCM/CBC/CTR；SHA-1/256/384/512、HMAC、HKDF、HMAC_DRBG |
| **Monocypher**（BSD-2 OR CC0） | `monocypher.c` + `optional/monocypher-ed25519.c` | RFC 8032 Ed25519（基于 SHA-512）、X25519 |
| （P2 再定）micro-ecc（BSD-2）或 libsecp256k1（MIT） | — | secp256k1（BearSSL 的 `ec_prime_i31` 只支持 NIST 曲线） |

**常数时间配置（必须钉死，不能用 BearSSL 的默认 vtable）**

- AES **只能**使用 `br_aes_ct_*`（bitsliced 实现）。`aes_small` / `aes_big` 是查表实现，不是常数时间。
- GHASH 使用 `br_ghash_ctmul32`。
- 大数运算：`i31` / `m31` 依赖 32×32→64 的 `UMULL` 是常数时间。BearSSL 明确指出 Cortex-M3 上它**不是**常数时间。**M33 是否常数时间，要在 M1 用 DWT 周期计数器、拿不同的操作数实测**；如果不是，就整体切换到 `i15` / `m15`（只用 32×32→32 的 `MUL`），代价是变慢。
- 在 `crypto_hal` 层对编译时选用的实现做 `_Static_assert` 或链接期检查，防止误用非常数时间实现。

**`crypto_hal.h` 规则**

- `apps/` 和 `transport/` **禁止** `#include` BearSSL 或 Monocypher 的头文件，CI 用 grep 检查。
- 接口只使用定长缓冲区和调用方提供的上下文，没有 malloc。敏感中间值在返回前清零。
- 熵源：固件端用 TRNG（`pico_rand`）为 HMAC_DRBG 播种，host 端用 `getentropy()`。不在每个字节上直接读取 TRNG。

**硬件 SHA-256：只做可选加速，不接入 BearSSL 内部**

- 你的方案在这里需要修正：BearSSL 的 HMAC、HKDF、HMAC_DRBG 和 RFC 6979 都要求 hash vtable 支持 `set_state()`（预计算的 ipad/opad 状态需要写回去），而且常常有两个 hash 上下文同时存在（HMAC 的内层和外层）。RP2350 的 SHA-256 引擎只有一个实例，`ResearchDocs` 中也没有说明它能载入任意中间状态（**需要按数据手册核实**）。
- 因此硬件 SHA-256 只用于顶层的一次性摘要（例如 authenticatorData 的哈希），由 `crypto_sha256_oneshot()` 选择后端。HMAC、KDF、DRBG 一律使用 BearSSL 软件实现。
- 在安全密钥里，哈希从来不是瓶颈，这一项的收益很小。如果 M1 实测加速效果不明显，就直接删掉，减少代码路径。

**RSA 密钥生成：放在 Core 1，不在 RNG 回调里驱动 USB（修正）**

你的方案是在 `br_prng_class.generate()` 回调里轮询 USB、发送保活。这在本项目中**不采用**，原因有三：

1. **回调间隔没有上界**。BearSSL 只在生成候选数等时机调用 RNG。一个候选数一旦通过筛选，接下来的若干轮 Miller-Rabin 要做完整的模幂，以 RSA-4096 的 2048-bit 素数为例，这里没有任何 RNG 调用，间隔估计在秒级。CTAPHID 要求约 100 ms 一次保活，这种做法保证不了。
2. **重入风险**。在密码运算的调用栈深处调用 `tud_task()`，会触发 TinyUSB 回调和新帧的分发，栈深度和状态都不可控。
3. 它违反约束 A：本质上是在一个长阻塞调用内部打补丁。

采用的做法如下：

- Core 1 运行 `br_rsa_i31_keygen`，Core 0 的主循环照常运行，保活自然不会中断，不需要任何特殊处理。
- 启动前由 Core 0 从 TRNG 取 seed，交给 Core 1 上独立的 HMAC_DRBG 实例。Core 1 **不访问任何共享外设和锁**，也不碰 Flash。
- 取消：Core 0 调用 `multicore_reset_core1()` 后清零 Core 1 的缓冲区。正因为 Core 1 不持有共享资源，这样重置是安全的。
- `generate()` 回调只用来更新一个“进度计数器”，供 LED 和调试观察。RNG 回调的这个思路保留，但只用在这里。
- host 端没有 Core 1，测试时直接同步调用。
- 注意：BearSSL 的 keygen 是一个整体函数，无法像 RS-Key 那样把 p 和 q 分到两个核上并行生成，**单核 RSA-4096 可能需要几十秒甚至更久**，M6 要实测。对于 geek 用户，文档同时给出“在主机上生成密钥再导入”的路线。

**X.509：设备上不生成证书（修正）**

- **FIDO attestation**：provision 时，设备在内部生成 attestation 密钥对，只把公钥导出。用户的 CA 直接对这个公钥签发证书（自己的 CA、设备就在手里，不需要 CSR 来证明私钥持有）。证书作为不透明的 blob 导入设备，响应时原样放进 `x5c`。如果没有导入证书，就退回 self attestation（不需要证书）。
- **PIV**：按 SP 800-73，证书由主机构造，卡只负责签 TBS；证书在卡上只是普通数据对象。Yubico 的 on-device attestation（`f9` 槽）属于私有扩展，不做。
- 因此设备端**不需要** X.509 编码器，DER 模板也不需要。唯一需要的 ASN.1 是 ECDSA 签名的 DER 编码（BearSSL 的 `*_asn1` 接口已提供）以及 PIV/OpenPGP 的 BER-TLV（`core/tlv.c`）。
- attestation 私钥**绝不**接受对任意数据签名的请求，以免成为签名预言机。

**风险与验证**

- BearSSL 上一个正式版本是 0.6（2018），上游开发不活跃。好在密码原语已经很稳定。应对方式：vendor 一个固定的 commit；用 **Wycheproof** 测试向量（ECDSA、ECDH、RSA、AES-GCM、HKDF、Ed25519、X25519）在 host 上做全量回归，并纳入 CI。
- RFC 6979 确定性 ECDSA 在故障注入下可能泄露私钥。这属于威胁模型之外的物理攻击，接受这个风险。

### Flash 布局（2 MB，初案）

| 区域 | 大小 | 说明 |
| :--- | :--- | :--- |
| 分区表 boot slots | 8 KB | picotool 固定保留 |
| Firmware | 1024 KB | C 实现预计远小于 RS-Key 的约 900 KB，余量留给 RSA/PIV |
| Data（LittleFS） | 888 KB | 加密记录 |
| Data（计数器环） | 128 KB | 签名计数器、磨损均衡 |

板级定义：自建 `boards/waveshare_rp2350_zero_cm.h`，`PICO_FLASH_SIZE_BYTES = 2 MB`，并在 `include(pico_sdk_import.cmake)` **之前**设置。WS2812 按 **GRB** 顺序。

---

## 5. 设备生命周期（geek 流程）

```
DEV（不烧任何 OTP，任意固件）
  → PROVISION：设备内生成 MKEK → 写 OTP → 校验 → 锁页
  → SEAL：用户用自己的 secp256k1 密钥签名 → 写 bootkey 哈希 + 设 rollback 版本
  → HARDEN：secure boot 生效 + 关闭调试 + 启用 glitch detector
```

每一步都要支持 `--dry-run` 和状态回读。每一步都**不可逆**，CLI 必须要求二次确认。

---

## 6. TODO（按里程碑）

### M0 基建
- [ ] `LICENSE`（MIT）、`THIRD_PARTY_NOTICES`、`docs/CLEAN_ROOM.md`、`docs/THREAT_MODEL.md`
- [ ] CMake 骨架：固件 target + host target；板级头（2 MB）；C17 + `-Werror`；`pico_enable_stdio_usb = 0`
- [ ] **job 框架**（约束 A）：`job_t`、单 job 调度、假时钟、超时/取消/BUSY 的 host 测试
- [ ] **OTP HAL + `otp_mock_ram`**（约束 B）：带物理语义的 mock 及其测试
- [ ] 锁定工具链版本（Arm GNU 14.2）与 pico-sdk tag；CI：固件构建 + host 测试 + fuzz 冒烟
- [ ] 向 pid.codes 申请 `1209:xxxx`

### M1 平台层
- [ ] TRNG 封装（`get_rand_128`）+ 自检
- [ ] BOOTSEL UP 采样（`flash_safe_execute`）+ 短按/长按判定，封装成 UP-wait job
- [ ] WS2812 PIO 驱动 + 状态机（空闲 / 等待触摸 / 处理中 / 错误）
- [ ] Flash 驱动 + LittleFS 移植 + 断电测试（随机掐电 1000 次）；实测扇区擦除的最坏耗时
- [ ] `otp_mock_flash` 后端
- [ ] 分区表 JSON + 嵌入 ELF 的构建步骤

### M2 USB 传输
- [ ] TinyUSB 复合描述符（先只开 HID-FIDO）
- [ ] CTAPHID：INIT / MSG / CBOR / PING / CANCEL / KEEPALIVE / WINK / LOCK、通道分配、超时、分包重组 + fuzz
- [ ] job 挂起期间自动发送 KEEPALIVE；CANCEL → `job.cancel()`

### M3 FIDO2 / U2F（P0）
- [ ] CBOR 编解码 + fuzz
- [ ] getInfo / makeCredential / getAssertion / getNextAssertion
- [ ] clientPIN v1/v2、pinUvAuthToken permissions、PIN 重试与锁定
- [ ] ES256 + EdDSA；非驻留凭据 ID 方案；驻留凭据存储
- [ ] credProtect、hmac-secret、credentialManagement、reset、selection
- [ ] U2F register / authenticate
- [ ] 互操作验证：python-fido2、libfido2 `fido2-token`、webauthn.io、`ssh-keygen -t ed25519-sk -O resident`、KeePassXC

### M4 安全生命周期
- [ ] MKEK 生成 / chaff / 锁页；存储层 AEAD（全部在 mock 上完成）
- [ ] OTP 单调 PIN 计数器：在 mock 上做完整测试，包括模拟 Flash 回滚的攻击用例
- [ ] `otp_real` 后端 + 三重闸门；**在牺牲板上做 PoC：raw 单 bit 烧写与回读**
- [ ] `omk` CLI：provision / seal / harden / status（含 dry-run）
- [ ] 签名流水线：嵌入分区表 → `picotool seal`（ELF→ELF）→ 转 UF2

### M5 CCID + OATH（P1）
- [ ] 自写 TinyUSB CCID class driver；扩展 APDU；job 挂起期间自动发送 Time Extension
- [ ] APDU 分发 + 应用选择；OATH（YKOATH）+ `omk oath` 客户端

### M6 OpenPGP（P1→P2）
- [ ] OpenPGP 3.4 ECC 部分、UIF、KDF-DO；`gpg --card-status` / 签名 / 解密 / ssh 验证
- [ ] RSA 2048/3072/4096（Core 1 job 中生成，支持取消），完成后实测耗时

### M7 PIV + 其他（P2）
- [ ] PIV；OpenSC `pkcs11-tool` / macOS 智能卡登录验证
- [ ] largeBlobs、minPinLength、alwaysUv、ES384/ES512/ES256K
- [ ] 键盘 HID：Yubico OTP（+ 自建 ykval 部署文档）/ HOTP / 静态密码；`omk otp` 配置
- [ ] seed 备份/恢复（BIP-39）；用户自建 CA 的 attestation

### M8 发布工程
- [ ] 可复现构建（Docker 或 Nix 锁定环境）、release 签名、SBOM
- [ ] 栈水位与 RAM/Flash 占用报告

**测试贯穿始终**：每个解析器（CBOR / APDU / TLV / CTAPHID）都必须有 fuzz 目标；host 端测试默认开启 ASan/UBSan；协议实现用规范附带的测试向量校验。

---

## 7. 决策记录

| # | 议题 | 结论 |
| :--- | :--- | :--- |
| 1 | 密码学依赖 | 拍板采用 BearSSL（MIT）+ Monocypher（BSD-2/CC0），零 malloc、严格常数时间，接口收拢于 `crypto_hal.h`（约束 C）。 |
| 2 | 冒用 Yubico VID/PID | 不做，只做协议兼容。 |
| 3 | OTP 单调 PIN 计数器 | 采纳，作为主打特性。 |
| 4 | 国密 / PQC | 砍掉。 |
| 5 | 语言版本 | C17。 |
| 6 | OTP 访问 | 必须经过 HAL；默认走 mock；真 OTP 有三重闸门（约束 B）。 |
| 7 | 耗时操作 | 采用非阻塞 job 模型，保活由传输层统一负责（约束 A）。 |
