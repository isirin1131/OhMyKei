# OhMyKei 方向与路线图（v2）

> 依据：`ResearchDocs/01~03` 及产品定位修正。状态：**方向已定**。

---

## 0. 一句话定位

**一个面向程序员、MIT 许可、C17 从零编写、跑在 RP2350-Zero-CM 上的开源硬件密钥：协议兼容做满，绝不能从 USB 被攻破；硬件层不假装自己是专用安全芯片（SE），只防住“20 分钟的 easy hack”以争取反应时间，靠一键熔断脚本（Kill-Switch）与可选心跳机制完成密钥遗失后的安全闭环。**

---

## 1. 三条底线

| 底线 | 具体做法 |
| :--- | :--- |
| **MIT 洁净室** | 只参照**规范**（CTAP 2.1/2.2、U2F、OpenPGP Card 3.4、NIST SP 800-73-4、YKOATH、Yubico OTP、CCID 1.1、ISO 7816-4）编写。canokey（Apache-2.0）和 RS-Key（**AGPL**）只用来理解架构、行为与踩坑点，**不复制、不逐行翻译**（Rust→C 逐行翻译仍可能构成衍生作品）。在 `docs/CLEAN_ROOM.md` 记录每个模块参照的规范章节。 |
| **依赖许可白名单** | 只接受 MIT / BSD / ISC / CC0 许可，**不引入 Apache-2.0**。当前清单：pico-sdk（BSD-3）、TinyUSB（MIT）、LittleFS（BSD-3）、BearSSL（MIT）、Monocypher（BSD-2 OR CC0）。随二进制附带 `THIRD_PARTY_NOTICES`。 |
| **程序员自主可控（无厂商 + 可随时熔断）** | 不内置任何厂商签名密钥、不依赖网页控制台或云端。硬件只是私钥的防远控/防误触容器，不是身家性命的单点故障：支持 BIP-39 种子主备同步，并提供**遗失后一键熔断脚本（自动吊销远端公钥/凭据）**与心跳扩展示例。 |

---

## 2. 安全哲学与威胁边界：做什么 / 不做什么

### 核心认知：通用 MCU 不是安全元件（SE），不卷边际效应极低的硬件军备竞赛

通用微控制器（如 RP2350、ESP32-S3）在物理设计上不可能与通过 CC EAL6+ 认证的专用加密芯片相比（例如此前 ESP32-S3 爆出硬件漏洞，导致以其为基础的硬件冷钱包全部面临物理攻破风险；RP2350 官方攻防赛也证实开盖与故障注入无法在通用 MCU 上根除）。

我们的用户是**程序员**，不是黑社会、不法分子或高价值地下钱庄。不需要假想这颗 30 元的开发板会被送进专业 Hacker Lab 拆焊芯片、打激光毛刺或上电子显微镜。因此，我们的安全策略明确聚焦为三层：

1. **USB 边界零妥协**：插在电脑上时，绝不能从 USB 接口被攻破（防木马静默调用、防钓鱼、防协议解析漏洞、防在线爆破 PIN）。
2. **硬件只防“20 分钟 Easy Hack”**：物理丢失后，确保捡到者或普通攻击者（stupid hacker）无法在 20 分钟内通过插 USB 敲命令（如 `picotool save --all`）或简单连线直接导出可用私钥，**为用户留出充裕的反应时间**。
3. **遗失即熔断（Kill-Switch）**：一旦确认密钥遗失，用户直接启动熔断脚本（或由心跳程序自动触发），在服务端撤回公钥与授权，彻底阻断硬件内密钥被利用的可能。

---

### ✅ 做（紧扣上述三层防线，高性价比）

1. **严防 USB 协议攻击面（最高优先级）**：
   - 所有 USB 输入解析器（CTAPHID、CBOR、CCID、APDU、BER-TLV）在 host 端脱离硬件编译，强制接入 **libFuzzer + ASan/UBSan** 持续模糊测试。
   - **强制物理在场确认（UP）**：所有签名、注册、解密等敏感操作必须物理按下 BOOTSEL 键，远程恶意软件无法静默盗用。
   - **PIN 失败锁定**：Flash 内维护 PIN 重试计数器（FIDO 8 次、OpenPGP 3 次），防 USB 在线暴力猜解；PIN 只存哈希或 KDF 参数，不存明文（OpenPGP 实现 KDF-DO）。
2. **挡住“20 分钟 Easy Hack”的轻量硬件防线**：
   - **静态 AEAD 加密落盘**：Flash 里的每条敏感记录用 AEAD（AES-GCM 或 ChaCha20-Poly1305）加密存储。主加密密钥由 **PIN（经 KDF）与设备随机密钥（MKEK）** 派生。即使攻击者拿到了整片 Flash 镜像，看到的也全是密文，20 分钟内绝无可能离线爆破出私钥。
   - **分区表围栏**：数据分区设置 `bootloader: ""`，挡住按住 BOOTSEL 插入电脑后一行 `picotool save --all` 直接拖走数据区。
   - **一键式基础锁板（`omk lock`）**：提供极简的 `omk lock` 脚本（生成随机密钥写入 OTP 并锁定该 page + 签发固件开启基础 Secure Boot 使分区表生效 + 关闭 SWD 调试口），堵死按住 BOOTSEL 刷自制固件、插杜邦线用 OpenOCD/picotool 顺手读内存这两条路。**开发板不锁；实际使用的 Key 必须锁。**
3. **遗失后的主动防御工具链（熔断脚本 + 心跳示例）**：
   - **密钥用途账本与一键熔断（`omk revoke`）**：记录该硬件密钥注册过的 GitHub / GitLab 账号、SSH 目标主机、GPG 公钥指纹及 WebAuthn 站点清单。遗失时一行命令批量调用 API 删公钥、清理服务器 `authorized_keys`、发布 GPG 吊销证书。
   - **心跳 / 死人开关示例（Heartbeat）**：提供可由用户自由定制的脚本模板（如定时检测硬件在位签名或远端心跳续期，超时未签到则自动触发告警或熔断脚本）。
4. **软件密码学基本功**：使用 BearSSL 常数时间算法实现（`br_aes_ct_*` 等）+ Monocypher、硬件 TRNG 播种、敏感内存用完即清零、看门狗。

---

### ❌ 不做（过度工程、收益极低或属于专业实验室攻防范畴）

| 项 | 理由 |
| :--- | :--- |
| **OTP 单调 PIN 失败计数器（及配套的 OTP HAL + Mock 框架）** | **已砍掉。** 原方案是为了防“攻击者用热风枪拆焊 2×3mm QSPI Flash 芯片、用编程器备份并反复回写快照以绕过 8 次 PIN 限制”。这需要专业拆焊台与耗时操作，完全不属于“20 分钟 easy hack”；为此设计按 bit 烧 OTP 与三套 Mock 属于典型的方向跑偏。PIN 计数直接存 Flash 即可。 |
| **OTP 正反码成对存放（Chaff）** | **已砍掉。** 这是为了对抗开盖后用聚焦离子束（FIB）/ 被动电压对比（PVC）电子显微镜读取反熔丝，纯属实验室级假想敌。 |
| **多阶段重型 OTP 固化仪式（`PROVISION → SEAL → HARDEN` 状态机）** | **已砍掉。** 不再把精力花在复杂的 OTP 生命周期管理、三重闸门和牺牲板测试上；简化为直接调用 `picotool` 的一键锁板脚本 `omk lock`。 |
| **微架构指令周期实测与降级（DWT 测 `UMULL`、降级 `i15`）、DPA 掩码、抗故障注入冗余计算** | **已砍掉。** 物理侧信道与电压/激光故障注入不在威胁模型内，软件层面直接使用 BearSSL 标准常数时间实现即可，不做微架构级折腾。 |
| **TrustZone Non-Secure 隔离 / Encrypted boot** | 同一颗裸片上隔离收益很小，且固件本身开源、秘密在加密数据区不在代码里。 |
| **NFC** | 板上没有 NFC 硬件。 |
| **WebUSB 网页控制台** | 和“干净、自托管”的定位冲突，管理统一走 CLI。 |
| **FIDO 的 PQC（ML-DSA） / 国密 SM2/SM3/SM4** | **已确认砍掉。** 目标客户端（浏览器、gpg、ssh）不通用，徒增代码体积与栈消耗。 |
| **冒用 Yubico VID/PID** | **已确认不做。** 只做协议层兼容（YKOATH / PIV / OpenPGP / OTP）。OATH 和 OTP 的管理由 `omk` CLI 承担；gpg、OpenSC、ssh、浏览器不受影响。 |
| **A/B 双固件槽** | bootrom 的 BOOTSEL 永远可以重刷，不会变砖；省下的空间留给数据区。 |

---

## 3. 功能范围（分档）

| 档 | 功能 |
| :--- | :--- |
| **P0：MVP（核心可用 + 熔断闭环）** | CTAPHID；CTAP 2.1（getInfo / makeCredential / getAssertion / getNextAssertion / clientPIN 协议 v1+v2 + token permissions / reset / selection / credentialManagement）；U2F；ES256 + EdDSA；驻留凭据（目标 ≥256，只受存储限制）；`credProtect`；`hmac-secret`；BOOTSEL 作为 UP；LED 状态指示；**`omk` 一键熔断脚本框架（SSH / GitHub / GitLab）与 BIP-39 种子备份/恢复** |
| **P1：程序员日常主力** | CCID；OATH（YKOATH）；OpenPGP 3.4 的 ECC 部分（Ed25519 / X25519 / P-256 / P-384，UIF，KDF-DO）；`largeBlobs`、`minPinLength`、`alwaysUv`；**GPG 吊销证书自动生成与一键熔断接入；心跳（Heartbeat）守护程序示例** |
| **P2：补全** | OpenPGP RSA-2048/3072/4096（密钥生成放在 Core 1）；PIV（9A/9C/9D/9E + retired 槽，ECC 与 RSA-2048，AES 管理密钥）；ES384 / ES512 / ES256K；键盘 HID：Yubico OTP（配合自建 ykval）/ HOTP / 静态密码；用户自建 CA 签发的 attestation 证书（设备只存储、不生成） |
| **砍掉** | 见 §2 的“不做”清单 |

**非驻留凭据的设计**：credential ID = `ver ‖ nonce ‖ MAC(K_mac, rpIdHash ‖ nonce ‖ alg ‖ flags)`，私钥 = HKDF(seed, nonce ‖ rpIdHash)。这样备份 seed 就等于备份了全部非驻留凭据，主/备两把 key 可以共享同一个 seed，遗失主 key 熔断后可立即启用备 key。

---

## 4. 架构与技术选型

```
CMakeLists.txt            顶层 CMake 构建定义（固件 + host 测试入口）
CMakePresets.json         fw-release / fw-debug / host / fuzz 四套 preset
cmake/pico_sdk.cmake      pico-sdk 定位与官方 import 桥接（不手写 SDK 源列表）
src/
  platform/   硬件平台层（BOOTSEL RAM 采样、TRNG、flash、USB 描述符）
  transport/  ctaphid.c  ccid.c  kbd_hid.c         ← TinyUSB 回调只做搬运
  core/       cbor.c  tlv.c  apdu.c  storage.c(AEAD+LFS)  crypto_hal.h + crypto_*.c
  apps/       fido2/  u2f/  oath/  openpgp/  piv/  otp/  mgmt/
host/         同一份 core+apps 在 macOS/Linux 本机编译 → 单元测试 + libFuzzer + ASan/UBSan
tools/omk/    Python CLI（MIT）：日常管理、BIP-39 备份恢复、凭据登记账本、一键熔断（revoke）、心跳示例、一键锁板
```

- **构建系统（CMake + Ninja）**：固件使用官方 `pico-sdk` 原生 CMake（`fw-release` / `fw-debug` preset）；Host 测试与 Fuzz 走同一工程的 `OMK_HOST_BUILD` 分支（`host` / `fuzz` preset），分别用 CTest + ASan/UBSan 与 libFuzzer。`src/` 只放项目自身 C17 源码，不含任何 SDK 构建胶水；`pico-sdk` 的板级宏解析、`version.h`、`config_autogen.h`、链接脚本与 SDK 源文件选择全部由 `pico_sdk_init()` / `pico_add_extra_outputs()` 负责。
- **直接复用官方 `pico-sdk` 内置的微雪板级定义与彩灯组件**：`pico-sdk` 2.3.1 已原生内置 `boards/waveshare_rp2350_zero.h`（定义了 GPIO 16 WS2812 等引脚）和 `pico_status_led`（`pico/status_led.h`，自动完成 PIO WS2812 GRB 驱动与 50µs 锁存延时）。CM 版与标准 Zero 的片上差异只有 Flash 大小（2MB vs 4MB），因此直接使用官方板级头，并在 target 上调用 `pico_override_flash_size(ohmykei 2097152)` 覆盖 Flash 区域即可，无需自造板级头或手写 PIO 驱动。
- **`pico-sdk` 硬件层与协议层解耦**：固件底层（`src/platform/`）完全基于官方 `pico-sdk`；而纯协议与状态机目录（`core/` 和 `apps/`）通过 `platform/` 抽象接口调用硬件，不直接 `#include "pico/..."`，从而让同一份协议代码也能在 Host 上原生编译并接入 `libFuzzer`。这是确保**“绝不能从 USB 被攻破”**的核心工程手段。
- **USB**：TinyUSB 提供复合设备。TinyUSB 主线**没有 CCID device class**，通过 `usbd_app_driver_get_cb` 自己实现一个精简版。
- **密码学**：BearSSL（MIT）+ Monocypher（BSD-2 OR CC0），不使用堆内存，所有调用都经过 `crypto_hal.h`，详见约束 C。
- **CBOR**：自写严格的 canonical 子集解析器，限制深度和长度，作为第一个 fuzz 目标。
- **存储**：LittleFS 存放 AEAD 加密记录；另外划一块小环形区专门写 FIDO 签名计数器，避免 LFS 元数据被频繁擦写。
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
- 已知阻塞源：Flash 擦除会暂停 XIP。规则是记录写入不放在 UP 等待中途；擦除按 4 KB 粒度切分。

### 架构硬约束 B：USB 边界零信任与 Fuzz 驱动

既然安全重心是**“绝不能从 USB 被攻破”**，所有外部字节流进入业务逻辑前必须经过严格验证：

- **零裸指针越界解析**：`core/cbor.c`、`core/tlv.c`、`core/apdu.c`、`transport/ctaphid.c`、`transport/ccid.c` 统一使用带边界游标（cursor/slice）的读取辅助函数，禁止手写裸指针偏移算术。
- **每个解析器与协议状态机必须配套 Fuzz 目标**：在 `host/fuzz/` 下为 CTAPHID 分包重组、CBOR 解码、FIDO2 请求分发、CCID 帧解析、APDU 命令路由分别建立 `libFuzzer` target，开启 `ASan + UBSan`，纳入 CI 门禁。
- **状态机防绕过测试**：针对“未验证 PIN 直接请求签名”、“未完成 UP 采样直接读取结果”、“跨通道/跨应用状态污染”编写专门的负向单元测试。

### 架构硬约束 C：密码学栈（纯 MIT/BSD/CC0、零 malloc）

**分工**

| 库 | 只引入的部分 | 负责 |
| :--- | :--- | :--- |
| **BearSSL**（MIT，固定到某个 commit 并 vendor 进仓库） | `src/int` `src/ec` `src/rsa` `src/symcipher` `src/hash` `src/mac` `src/kdf` `src/rand`，不要 TLS / X.509 层 | RSA-2048/3072/4096（`br_rsa_i31_keygen`、原始私钥运算、PKCS#1 v1.5、PSS、OAEP）；P-256 / P-384 / P-521 ECDSA（RFC 6979）与 ECDH；AES-GCM/CBC/CTR；SHA-1/256/384/512、HMAC、HKDF、HMAC_DRBG |
| **Monocypher**（BSD-2 OR CC0） | `monocypher.c` + `optional/monocypher-ed25519.c` | RFC 8032 Ed25519（基于 SHA-512）、X25519、ChaCha20-Poly1305 |
| （P2 再定）micro-ecc（BSD-2）或 libsecp256k1（MIT） | — | secp256k1（BearSSL 的 `ec_prime_i31` 只支持 NIST 曲线） |

**`crypto_hal.h` 规则**

- `apps/` 和 `transport/` **禁止** `#include` BearSSL 或 Monocypher 的头文件，CI 用 grep 检查。
- 直接选用 BearSSL 提供的常数时间实现（`br_aes_ct_*`、`br_ghash_ctmul32`、`i31`），不使用查表版 `aes_small`/`aes_big`。
- 接口只使用定长缓冲区和调用方提供的上下文，没有 malloc。敏感中间值在返回前清零。
- 熵源：固件端用 TRNG（`pico_rand`）为 HMAC_DRBG 播种，host 端用 `getentropy()`。
- **硬件 SHA-256**：只做可选的顶层一次性摘要加速（`crypto_sha256_oneshot()`），不侵入 BearSSL 内部 vtable；若实测收益不明显则直接省去。

**RSA 密钥生成：放在 Core 1，不在 RNG 回调里驱动 USB**

- Core 1 运行 `br_rsa_i31_keygen`，Core 0 的主循环照常运行，USB 保活自然不会中断。
- 启动前由 Core 0 从 TRNG 取 seed，交给 Core 1 上独立的 HMAC_DRBG 实例。Core 1 **不访问任何共享外设和锁**，也不碰 Flash。
- 取消：Core 0 调用 `multicore_reset_core1()` 后清零 Core 1 的缓冲区。
- 对于不愿等待片上生成 RSA-4096 的用户，`omk` 同时支持在主机上生成密钥再安全导入。

**X.509：设备上不生成证书**

- **FIDO attestation**：设备只存储外部导入的证书 blob 并原样放进 `x5c`；未导入时退回 self attestation。
- **PIV**：证书由主机构造，卡只负责签 TBS 和作为数据对象存储。
- 设备端不需要 X.509 编码器。

**验证**：用 **Wycheproof** 测试向量（ECDSA、ECDH、RSA、AES-GCM、HKDF、Ed25519、X25519）在 host 上做回归测试，并纳入 CI。

### Flash 布局（2 MB）

| 区域 | 大小 | 说明 |
| :--- | :--- | :--- |
| 分区表 boot slots | 8 KB | picotool 固定保留 |
| Firmware | 1024 KB | C 实现体积充裕 |
| Data（LittleFS） | 888 KB | AEAD 加密记录 |
| Data（计数器环） | 128 KB | 签名计数器、磨损均衡 |

板级定义：直接复用 `pico-sdk` 内置的 `boards/waveshare_rp2350_zero.h` + `pico_status_led`（`pico/status_led.h`），并在 target 上调用 `pico_override_flash_size(ohmykei 2097152)`，把标准 Zero 的 4 MB 覆盖为 CM 版的 2 MB。

---

## 5. 程序员工作流：防 20 分钟 Easy Hack + 一键熔断闭环

我们不要求用户经历繁琐的硬件量产固化仪式，而是提供一套符合程序员直觉的**“轻量锁板 + 遗失即熔断”**工作流：

```
1. 刷机与初始化（5 分钟）
   刷入 UF2 → 设置 PIN → 生成主种子（BIP-39 助记词离线备份，可选同步到备用 Key）
   →（开发板跳过；实际使用的 Key 必须执行）运行 `omk lock` 一键写入 OTP 随机根密钥、启用分区围栏、关闭 SWD

2. 日常绑定与记账
   生成 SSH (`ed25519-sk`) / GPG / WebAuthn 凭据
   → `omk` 本地账本自动记录该 Key 绑定的服务（GitHub、GitLab、目标服务器、GPG 指纹、站点列表）

3. 遗失应急：20 分钟安全窗口内完成熔断
   [硬件侧] 分区围栏 + AEAD 密文存储 + PIN 锁定 → 捡到者无法在 20 分钟内通过 USB 或简单工具导出密钥
   [用户侧] 运行 `omk revoke`（或由心跳程序自动触发）：
            ├── 自动调用 GitHub / GitLab API 删除对应 SSH / GPG 公钥
            ├── 自动通过备用通道连接受管服务器，从 `~/.ssh/authorized_keys` 移除公钥
            ├── 自动发布预生成的 OpenPGP 吊销证书
            └── 输出已绑定 WebAuthn 的站点清单，引导用备用 Key 登录并踢掉旧 Key
```

---

## 6. TODO（按里程碑）

### M0 基建
- [ ] `LICENSE`（MIT）、`THIRD_PARTY_NOTICES`、`docs/CLEAN_ROOM.md`、`docs/THREAT_MODEL.md`
- [x] **CMake 构建骨架**：`fw-release`/`fw-debug` 固件 target + `host`/`fuzz` 本机构建；复用 `pico-sdk` 内置 `boards/waveshare_rp2350_zero.h` + `pico_override_flash_size()` 覆盖 2 MB Flash，并用 `pico/status_led.h` 完成板载 WS2812B 点灯验证
- [ ] **job 框架**（约束 A）：`job_t`、单 job 调度、假时钟、超时/取消/BUSY 的 host 测试
- [ ] **Fuzz 与测试基建**（约束 B）：host 端 `libFuzzer + ASan/UBSan` 编译管线与回归脚本
- [ ] 锁定工具链版本与 pico-sdk tag；CI：固件构建 + host 测试 + fuzz 冒烟
- [ ] 向 pid.codes 申请 `1209:xxxx`

### M1 平台层与防 Easy Hack 存储
- [ ] TRNG 封装（`get_rand_128`）+ 自检
- [ ] BOOTSEL UP 采样（`flash_safe_execute`）+ 短按/长按判定，封装成 UP-wait job
- [ ] 基于 `pico/status_led.h` 的状态指示灯状态机（空闲 / 等待触摸 / 处理中 / 错误）
- [ ] Flash 驱动 + LittleFS 移植 + **AEAD 记录加密层（基于 PIN KDF + 片上随机密钥）** + 断电测试
- [ ] 分区表 JSON（数据分区 `bootloader: ""` 禁止 BOOTSEL 导出）+ 嵌入 ELF 的构建步骤

### M2 USB 传输（防 USB 攻破核心层）
- [ ] TinyUSB 复合描述符（先只开 HID-FIDO）
- [ ] CTAPHID：INIT / MSG / CBOR / PING / CANCEL / KEEPALIVE / WINK / LOCK、通道分配、超时、分包重组 + **fuzz**
- [ ] job 挂起期间自动发送 KEEPALIVE；CANCEL → `job.cancel()`

### M3 FIDO2 / U2F（P0）
- [ ] CBOR 编解码 + **fuzz**
- [ ] getInfo / makeCredential / getAssertion / getNextAssertion + **协议状态机 fuzz**
- [ ] clientPIN v1/v2、pinUvAuthToken permissions、Flash PIN 重试计数与锁定
- [ ] ES256 + EdDSA；非驻留凭据 ID 方案；驻留凭据存储
- [ ] credProtect、hmac-secret、credentialManagement、reset、selection
- [ ] U2F register / authenticate
- [ ] 互操作验证：python-fido2、libfido2 `fido2-token`、webauthn.io、`ssh-keygen -t ed25519-sk -O resident`、KeePassXC

### M4 `omk` 程序员工具链：备份、一键熔断与心跳（P0）
- [ ] `omk` CLI 基础框架与设备状态查询
- [ ] **密钥绑定账本与一键熔断脚本（`omk revoke`）**：
  - GitHub / GitLab SSH & GPG Key 自动摘除插件
  - 远端服务器 `~/.ssh/authorized_keys` 批量清理脚本
  - WebAuthn 绑定站点清单管理与快速吊销引导
- [ ] **心跳 / 死人开关示例（`examples/heartbeat/`）**：本地定时在位检测与远端超时自动触发熔断的参考实现
- [ ] BIP-39 种子备份与恢复（支持主备两把 Key 快速同步）
- [ ] 极简锁板命令（`omk lock`：封装 `picotool` 写入 OTP 随机根密钥并锁定该 page、签名分区表、关闭 SWD）

### M5 CCID + OATH（P1）
- [ ] 自写 TinyUSB CCID class driver；扩展 APDU；job 挂起期间自动发送 Time Extension + **CCID/APDU/TLV fuzz**
- [ ] APDU 分发 + 应用选择；OATH（YKOATH）+ `omk oath` 客户端

### M6 OpenPGP（P1→P2）
- [ ] OpenPGP 3.4 ECC 部分、UIF、KDF-DO；`gpg --card-status` / 签名 / 解密 / ssh 验证
- [ ] OpenPGP 吊销证书自动预生成并接入 `omk revoke` 一键熔断
- [ ] RSA 2048/3072/4096（Core 1 job 中生成，支持取消；同时提供主机生成后导入的快捷命令）

### M7 PIV + 其他（P2）
- [ ] PIV；OpenSC `pkcs11-tool` / macOS 智能卡登录验证
- [ ] largeBlobs、minPinLength、alwaysUv、ES384/ES512/ES256K
- [ ] 键盘 HID：Yubico OTP（+ 自建 ykval 部署文档）/ HOTP / 静态密码；`omk otp` 配置
- [ ] 用户自建 CA 的 attestation

### M8 发布工程
- [ ] 可复现构建（Docker 或 Nix 锁定环境）、release 签名、SBOM
- [ ] 栈水位与 RAM/Flash 占用报告

---

## 7. 决策记录

| # | 议题 | 结论 |
| :--- | :--- | :--- |
| 1 | 密码学依赖 | 采用 BearSSL（MIT）+ Monocypher（BSD-2/CC0），零 malloc、选用自带常数时间实现，接口收拢于 `crypto_hal.h`（约束 C）。 |
| 2 | 冒用 Yubico VID/PID | 不做，只做协议兼容。 |
| 3 | 硬件安全边界与防丢策略 | **修正方向**：承认通用 MCU 物理局限，砍掉 OTP 单调 PIN 计数器、OTP Mock 框架、PVC chaff、微架构侧信道实测等低边际收益项。硬件层只防“20 分钟 easy hack”（AEAD 静态加密 + 分区围栏禁 BOOTSEL 导出 + 关 SWD；开发板不锁，实际使用的 Key 必须 `omk lock`），核心防丢闭环依靠**“一键熔断脚本（`omk revoke`）+ 可选心跳程序 + BIP-39 主备切换”**。 |
| 4 | 国密 / PQC | 砍掉。 |
| 5 | 语言版本 | C17。 |
| 6 | USB 攻击面防御 | 最高安全优先级是“绝不能从 USB 被攻破”：`core/` 与 `apps/` 100% 在 host 编译，所有解析器与协议状态机强制配备 libFuzzer + ASan/UBSan（约束 B）。 |
| 7 | 耗时操作 | 采用非阻塞 job 模型，保活由传输层统一负责（约束 A）。 |
| 8 | 构建系统 | **采用 CMake + Ninja**：固件直接使用官方 `pico-sdk` 原生 CMake（`pico_sdk_init()` + `pico_add_extra_outputs()`），Host 测试与 Fuzz 走同一工程的 `host`/`fuzz` preset（CTest + clang ASan/UBSan + libFuzzer）。放弃 Meson 桥接，避免手工复刻 SDK 的 defines/includes/sources。 |
