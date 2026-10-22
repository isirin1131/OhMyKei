# RS-Key 与 pico-keys / pico-fido 生态深度技术调研报告

**文档编号**：OHMYKEI-DOC-03  
**项目名称**：OhMyKei (基于 RP2350-Zero-CM 的开源硬件安全密钥)  
**更新日期**：2026-10-22  
**状态**：已核对（2026-10-22；依据 RS-Key `960b20a` / v0.4.11、pico-fido 上游记录、RP2350 数据手册）  

---

## 一、 背景与定位：开源安全密钥的范式转移

### 1. 为什么会出现 RS-Key？pico-keys 的商业化与双重许可风波
在硬件安全密钥领域，商业产品（如 YubiKey、Nitrokey、SoloKey）虽然功能完善，但固件通常为闭源“黑盒”，且厂商常通过人为划分产品线限制容量（例如仅支持 25~32 个驻留凭据）。

2024~2025 年初，由 Pol Henarejos 开发的 `pico-fido` 和 `pico-openpgp`（基于 Raspberry Pi Pico / RP2040，C 语言编写）迅速走红，证明了仅需 5 美元的通用微控制器就能实现与主流浏览器、`ssh-keygen -t ed25519-sk`、`gpg` 和 `ykman` 兼容的硬件认证器。TheMaxMur 参与了测试与问题定位，并提交了 Linux Firefox 下认证失败的 [pico-fido#129](https://github.com/polhenarejos/pico-fido/issues/129)；**修复本身由维护者完成**（commit `64f371e`），根因是固件在 `epAtt:false` 时仍返回该字段，触发 authenticator-rs 的 “trailing data” 报错。

**2025 年 10 月 26 日**，`pico-fido` 提交了 `Update license models and add ENTERPRISE.md`，同日晚些时候又把许可证从 **GPLv3 改为 AGPLv3**。需要准确理解这次变化：

1. **代码仍然公开**：`pico-fido` 仓库保持公开，许可证为 AGPLv3，2026 年仍在发布 v8.x（含 UF2）。所谓“Enterprise Edition”是对同一份代码的**商业许可**，没有另开闭源分支。
2. **合并仓库改为二进制分发**：整合 FIDO + OpenPGP 的 `polhenarejos/pico-fido2` 只剩 3 个 Markdown 文件 + `.github/FUNDING.yml`，v7.0/v7.2 的 Release **没有任何附件**（tag 的自动源码包只含这几个 md 文件）。官方不再在该仓库提供可构建源码；社区固件仍以 AGPLv3 分发。
3. **PicoKey App 是专有二进制**：按设备/席位收费（单设备 €29.49、主备双设备 €49.49，许可证与板子注册绑定）。维护者在 issue #245 明确说：“the firmware remains fully open, and the app is not strictly required”；官网也仍提供 Community firmware（AGPLv3）免费下载。社区固件并不要求通过专有客户端或单芯片授权码获取。
4. **企业证明属于开源固件功能**：`pico-fido2` README 的功能列表里就有 “Enterprise attestation”。PQC 在 `ENTERPRISE.md` 中是“可选企业组件”，但不能据此说社区版完全没有 PQC 代码（pico-keys-sdk 是 AGPLv3，RS-Key 也提供 `-pqc.uf2`）。

对 DIY 硬件安全密钥而言，**“能够逐行审计每一字节固件”确实是最重要的护城河**。这次变化主要影响“一个仓库拖下来即可构建、可逐行审计”的体验；代码本身仍然可见。TheMaxMur 因此决定用纯 Rust 从零重写，由此诞生了 **RS-Key**。

### 2. RS-Key 的技术选型与法律架构
RS-Key 在架构设计与法律授权层面做出了严格的不可逆约束：
- **不可逆的开源约束（AGPL-3.0-only）**：由于继承了原 pico-keys 协议与文件结构的衍生工作，根据 AGPLv3 传染性条款，RS-Key 永久保持 AGPL-3.0-only。项目不设立贡献者许可协议（CLA），贡献者各自保留版权，从法律层面杜绝了任何维护者未来单方面转为专有商业闭源的可能性。
- **纯 Rust 嵌入式栈（`no_std`）**：
  - **异步执行器与 HAL**：完全摈弃 upstream 的 C 语言 pico-sdk 及 TinyUSB，改用 `embassy-executor`、`embassy-rp` 与 `embassy-usb`。Rust 能消除大部分缓冲区溢出、释放后使用（UAF）等 C 语言类缺陷，但**不是绝对保证**：仓库仍有明确记录并逐项审计的 `unsafe` 点，逻辑错误与副作用也不在类型系统保护范围内。
  - **双执行器设计**：采用高优先级 `InterruptExecutor`（负责 USB 传输、CCID/CTAPHID keepalive 保持、LED 状态动画）+ 低优先级 `ThreadExecutor`（Worker 独占 Flash 读写与 TRNG 访问），避免引入传统多线程互斥锁，降低死锁风险。
  - **密码学与编解码库**：minicbor（安全 CBOR 编解码）、RustCrypto（`p256`/`p384`/`p521`/`k256`/`ed25519-dalek`）、自研 `rsk-rsa`（有常数时间审计与每操作盲化；残余风险为源码级论证，未经第三方审计）、以及 `sequential-storage` 磨损均衡 Flash 存储引擎。
  - **多核加速**：Core 0 执行主业务逻辑；Core 1 仅在生成 RSA 密钥时被激活，双核并行竞速寻找素数，将 RP2350 上的 RSA-2048 密钥生成平均耗时从 ~8.9s 降低到 ~4.3s（加速 2.07 倍）。

---

## 二、 RS-Key 在 RP2350 上的功能实现与硬件适配

### 1. 协议全栈功能实现
RS-Key 将 RP2350 虚拟为一个复合 USB 设备（Composite Device），同时提供 FIDO HID、CCID 智能卡以及 USB HID 键盘三个接口：

1. **FIDO2 / WebAuthn / U2F**：
   - 完整支持 CTAP 2.0 / 2.1 / 2.3 规范及 U2F（CTAP1）。
   - **Passkey 驻留密钥（Resident Keys / Discoverable Credentials）**：Flash 容量受限上限高达 256 个凭据。
   - **多算法支持**：ES256 (P-256)、Ed25519、ES384 (P-384)、ES512 (P-521)、ES256K (secp256k1)。
   - **OpenSSH 硬件密钥**：原生兼容 `ssh-keygen -t ed25519-sk` 与 `ecdsa-sk`。
   - **高级扩展特性**：支持 `credProtect` 凭据保护等级、`hmac-secret`（用于 KeePassXC、Bitwarden 离线数据库解密）、`largeBlobKey` / `largeBlobs`（CTAP 2.1 设计）、`alwaysUv`（强制用户验证）。另有一个编译期 `largeblob-ext` 选项可切到 CTAP 2.3 §12.4 的 per-credential `largeBlob` 扩展；二者**互斥**，且默认的 2.1 设计才是当前浏览器普遍支持的。
2. **OpenPGP Card 3.4 规范**：
   - 支持签名（Signature）、解密（Decryption）、认证（Authentication）三组密钥槽位。
   - 支持 RSA-2048/3072/4096，以及 ECC 椭圆曲线（NIST P-256/384/521、Curve25519 / Ed25519、secp256k1）。
   - 支持 UIF（User Interaction Flag）触控策略，确保每次签名必须物理按下按键。
3. **PIV（FIPS 201 个人身份验证智能卡）**：
   - 支持 24 个槽位（Card Authentication 9A、Digital Signature 9C、Key Management 9D、Card Auth 9E 等），支持 X.509 证书加载。
   - 原生兼容 OpenSC `pkcs11-tool`、macOS `sc_auth` / `pivtoken.appex` 及 `ykman piv`。
4. **OATH 认证**：
   - 支持最多 255 个 TOTP（基于时间）和 HOTP（基于计数）账户。
   - 支持触控展示口令与密码保护，兼容 Yubico Authenticator 客户端。
5. **Yubico-style OTP**：
   - 提供 4 个独立配置槽位，支持 AES-128 OTP 令牌生成或静态密码。
   - 支持以 USB 键盘接口（HID Keyboard）直接向主机自动键入 OTP 字符串。触发方式：槽 1/2 由短按/长按触发；槽 3/4 只能通过 slot-offset APDU 访问（`ykman otp` 也只认识槽 1/2）。
6. **抗量子后量子密码（Post-Quantum Cryptography, PQC）**：
   - **完全实现 FIPS 204 ML-DSA**：包括 ML-DSA-44 (COSE -48)、ML-DSA-65 (COSE -49)、ML-DSA-87 (COSE -50)。
   - **嵌入式流式极简优化**：自主编写的 `rsk-mldsa` crate 在运行时动态流式生成矩阵 $\mathbf{A}$，使得最庞大的 ML-DSA-87 keygen+sign 峰值栈帧控制在 123 KiB，能够完全在 RP2350 的 520 KiB SRAM 中完成运算。
7. **BIP-39 / SLIP-39 助记词备份与恢复**：
   - 彻底打破商业厂商“密钥不可导出”的产品锁定：支持将 FIDO 主种子以标准 BIP-39 / SLIP-39 助记词导出或在新设备上恢复，解决密钥丢失导致数字身份锁死的痛点。
   - 支持 At-rest soft-lock（以用户主密码对 Flash 内的 FIDO seed 做 ChaCha20-Poly1305 封装，密钥仅在解锁后驻留 RAM）。

---

### 2. 针对 2MB Flash（如 Waveshare RP2350-Zero-CM）的官方适配与编译细节

RP2350 开发板具有多种 Flash 容量规格：主流开发板多为 4MB/16MB，而许多微型形态板卡（如 **Waveshare RP2350-Zero-CM**、Seeed Studio XIAO RP2350）仅搭载了 **2MB (16Mbit) SPI Flash**。

#### 1. 存储冲突原因与分析
RS-Key 内部规划了两个基于 `sequential-storage` 的 KV 分区：
- `KVMAIN`（主凭据存储：Passkeys、OpenPGP、PIV 密钥等）
- `KVCNT`（防磨损高频单调计数器：128KB）

在默认的 4MB 编译配置下：
$$\text{Flash: } 4096\text{KB} = \text{Code: } 2560\text{KB} + \text{KVMAIN: } 1408\text{KB} + \text{KVCNT: } 128\text{KB}$$
如果直接将该配置套用到 2MB（2048KB）芯片上，1408KB + 128KB = 1536KB 的 KV 空间将仅留下 **512KB** 给代码段，而 RS-Key 编译生成的 release ELF/UF2 镜像通常在 **~900KB** 左右，直接导致链接器报错（`region 'FLASH' overflowed`）。

#### 2. 官方适配方案：`FLASH_SIZE=2M KVMAIN=896K`
RS-Key 在 `build.rs` 中实现了动态 Flash 布局重计算，并专门为 2MB 芯片定制了适配参数：
- **配置参数**：`FLASH_SIZE=2M KVMAIN=896K`
- **空间划分**：
  $$\text{Total 2048KB} = \text{Code: } 1024\text{KB} + \text{KVMAIN: } 896\text{KB} + \text{KVCNT: } 128\text{KB}$$
- **容量评估**：虽然 `KVMAIN` 从 1408KB 压缩到 896KB，但由于一个 Passkey 记录仅占约数百字节，即使存满全部 256 个 Resident Credentials、所有 PIV 槽位和 255 个 OATH 令牌，整体持久化数据总量也仅需 300~400 KB（上游估算），**896KB 容量绰绰有余**。
- **两个“分区”不是一回事**：`KVMAIN`/`KVCNT` 是 RS-Key 应用层的 KV 存储分区，由 `build.rs` 写入 `memory.x`；RP2350 partition table 是 bootrom 层的访问控制表，由 `scripts/pt.sh` 在链接后嵌入 ELF。前者决定“数据存在哪”，后者决定“BOOTSEL 能不能读写”。
- **发布渠道**：官方 CI 流水线在每个 GitHub Release 中直接提供编译好的专属预构建固件：**`rs-key-v0.4.11-2mb.uf2`**（文件名带 `v`）。

#### 3. 板载外设与引脚配置
对于 Waveshare RP2350-Zero-CM 等板卡：
- **状态指示灯（RGB WS2812）**：默认引脚为 **GPIO 16**（Waveshare RP2350-Zero / RP2350-One / Zero-CM 的板载布局一致）。颜色编码默认 `LED_ORDER=rgb`；RP2350-One 恰好是 rgb，但标准 WS2812B 是 **GRB**。Zero-CM 使用 WS2812B，**建议构建时加 `LED_ORDER=grb`**，或运行时用 `rsk hw --led-order grb` / PicoForge 修正；否则可能红绿互换。
- **用户在场检测（User Presence, UP）**：默认复用微控制器的 **BOOTSEL** 物理按键（内部通过 QSPI 采样读取）。在执行 WebAuthn 注册、签名、PIV 操作时，必须物理按下 BOOTSEL，防止远程攻击者未经许可静默签名。同时支持配置外部电容触控或独立 GPIO 按键（`PRESENCE_PIN`）。

---

## 三、 RP2350 硬件安全能力剖析与“甜点”边界

### 1. RP2350 的核心安全资产
RP2350 在前代 RP2040 的基础上大幅提升了安全性，引入了面向现代物联网的硬件安全子系统：
1. **8KB OTP（One-Time Programmable 反熔丝）**：数据手册 §13 明确为 8 kB，物理上是 4096 × 24-bit rows（ECC 后可用 8192 B）。它存放 boot key 指纹、`SECURE_BOOT_ENABLE`/`DEBUG_DISABLE` 等安全标志、可选的 boot decryption key、每设备唯一 ID 等。**注意**：`MKEK`/`DEVK` 不是 RP2350 的架构术语，而是 PicoKeys/RS-Key 的软件命名（OTP page 58，行 `0xE80`/`0xE90`）。
2. **硬件安全引导（Secure Boot）**：Bootrom 对固件镜像做 **ECDSA secp256k1 + SHA-256** 验签，**不是 Ed25519，也不是 P-256**（数据手册 §10.1.1/§5.1.8；picotool 也只接受 secp256k1 私钥）。使能生产模式后，未签名或篡改镜像无法启动。
3. **加密启动（Encrypted Boot）**：RP2350 支持把加密镜像从外部 QSPI Flash 载入 SRAM 后原地解密，解密密钥存放在 OTP 并可被 soft-lock；**不支持加密 XIP**。RS-Key 的“静态加密”是固件层方案：`kbase = HKDF(serial_hash, OTP master key)`，PIV 密钥用 AES-GCM、FIDO seed 的 soft-lock 用 ChaCha20-Poly1305；它不是芯片的 encrypted boot。
4. **ARM TrustZone-M**：Cortex-M33 提供硬件级安全/非安全隔离，但 **RS-Key 没有使用 Non-Secure world**，全部运行在 Secure 态，依靠 secure boot + OTP + 分区表防护。另外，pico-sdk 2.3.1 没有 `rp2350-arm-ns` 平台，想真正跑 NS world 需要自定义启动代码与 veneer，不能只靠 CMake 开关。分区表对 BOOTSEL 的隔离由 bootrom 强制执行，但**只有开启 secure boot 时才是真屏障**（见下文）。
5. **硬件加速器与真随机数发生器（TRNG）**：熵源是内部 Ring Oscillator（ROSC），经采样/条件化后输出 192 bit 熵；数据手册 §12.12 声明其符合 FIPS 140-2、BSI AIS-31 与 NIST SP 800-90B（这是 IP 块的合规声明，不是芯片认证）。另有硬件 SHA-256 引擎。

---

### 2. RP2350 不是专用安全元件（Secure Element, SE）：深度安全攻防复盘

虽然 RP2350 具备安全特性，但从微电子与芯片物理设计上看，**它依然是一颗通用微控制器（MCU），而非通过通用准则（Common Criteria EAL6+）认证的安全元件（SE，如 NXP SE050、Microchip ATECC608、ST33）**。

#### 1. RP2350 Hacking Challenge 的实验结论
Raspberry Pi 官方在 2024 年以 **10,000 美元**悬赏发起 RP2350 攻防挑战赛；到期无人领取后延期并把奖金**翻倍到 20,000 美元**。最终收到 4 份有效提交，官方决定**每份都按 20,000 美元全额支付**，合计 **80,000 美元**。

- **A2 步进芯片的漏洞与故障注入**：
  - **电压故障注入（VFI）**：Aedan Cullen 在 `USB_OTP_VDD` 上精确掉电，利用 guard word `0x333333` 的保持效应覆盖 `CRIT0/CRIT1`，令 `RISCV_DISABLE`/`ARM_DISABLE` 置位、`DEBUG_DISABLE` 清零，随后 dump OTP 秘密（**E16**）。E16 由 **A3 硅片**修复。
  - **Bootrom 单指令故障**：Marius Muench 用**电压毛刺**跳过 `reboot()` 路径中的**一条指令**，使 bootrom 误走 `REBOOT_TYPE_PC_SP`，在 Secure 态执行攻击者代码（**E20**）。E20 由 **A3 bootrom** 缓解。
  - **激光故障注入（LFI）**：Kévin Courdesses 用激光在签名校验前注入单次故障，使 hash 覆盖**攻击者控制的数据**，从而让未签名固件被执行（**E24**）。E24 由 **A4 bootrom** 缓解（datasheet 用 “Mitigate”，不是 “Fix”）。
  - **聚焦离子束（FIB）与被动电压对比（PVC）**：IOActive 对芯片开盖后，用 FIB/PVC 读出的是**相邻两个反熔丝单元的按位 OR**，不是逐位直接读出；缓解手段是把密钥与反码成对存放（chaff），让每对读出恒为 1。
  - **EMFI 双故障**：Hextree / Thomas Roth 在比赛外发现，用电磁故障注入可阻止 BOOTSEL 进入时正确锁定 OTP page，从而读写本应受保护的 OTP（**E21**）。E21 由 **A3 bootrom** 缓解。
- **A3 / A4 的真实差异**：
  - **A3** 有硬件修复/缓解（E3、E9 修复；E16 缓解；E10/E13/E14/E15/E19/E20/E21/E22/E23/E26 bootrom 修复/缓解）。
  - **A4 没有任何硬件改动**（datasheet Appendix C.3.1 原文：“This stepping has no hardware changes.”），只更新 bootrom：修复 E18、缓解 E24、修复 E25。当前 Zero-CM 原理图标注 `RP2350A0A4`，所以这块板已包含 A3 硅片 + A4 bootrom 的缓解。
  - **A4 仍未修复**：E17、E28；IOActive 的 PVC/开盖读取只能靠 chaff 和每设备密钥缓解。
- **无法防范的物理局限**：开盖（Decapping）、FIB/PVC 微探针、激光/电压/电磁故障注入（LFI/VFI/EMFI）以及高精度 DPA/EM 侧信道，在没有有源屏蔽层与传感器网格的通用 MCU 上无法靠软件消除。注意 EMFI 属于**故障注入**，不是侧信道；DPA 才是侧信道。
- **Flash 物理回滚与单调计数器缺失（Snapshot Rollback）**：
  - Token2 的 [Issue #37](https://github.com/TheMaxMur/RS-Key/issues/37) 标题为 `T2-SA-RP2350-Dec2025`，正文明确说“Havent had a chance to test yet”，详细链路来自其 advisory，且该 advisory 主要针对 **pico-fido**。典型路径是 BOOTSEL 下 `picotool save --all` 整片 dump，猜 PIN 到锁定后 `picotool load` 回滚，计数器被重置；拆焊后直接读取也可行。
  - **根本原因**：通用 MCU 缺少 SE 特有的“硬件级防篡改单调计数器”。RS-Key 的应对是 OTP-seeded PIN verifier + 分区表围栏 + `strong-pin`/soft-lock；**没有**硬件单调计数器。分区表只有在 secure boot 开启时才是真屏障；否则攻击者可刷一个权限宽松的分区表绕过。即使开启 secure boot，拆 Flash 做物理克隆/回滚仍可行。

---

### 3. DIY 安全 Key 的安全威胁模型与“甜点”定位

基于上述分析，可以清晰地勾勒出基于 RP2350 的 DIY 硬件安全密钥（如 OhMyKei / RS-Key）的**最佳安全甜点（Sweet Spot）**：

```
+--------------------------------------------------------------------------+
|                      威胁模型分界线 (Threat Boundaries)                   |
+--------------------------------------------------------------------------+
|  ✅ 能够有效防范 (Sweet Spot)                                            |
|   1. 远程木马注入与恶意软件窃密（必须物理按下 BOOTSEL 才能完成认证）       |
|   2. 凭据被盗与钓鱼攻击（FIDO2 / WebAuthn 基于域名绑定的公钥密码学体系）    |
|   3. 弱密码碰撞与凭据填充攻击                                            |
|   4. 内存破坏漏洞（Rust no_std 大幅降低溢出/UAF 类问题；仍有受审计的 `unsafe`，不能承诺根绝） |
|   5. 普通物理丢失场景下的数据提取（**需先完成 OTP MKEK 烧录 + page 58 锁定 + secure boot**；未固化的开发板 Flash dump 仍可读） |
+--------------------------------------------------------------------------+
|  ❌ 明确无法防范 (Out of Scope / 属于硬件物理局限)                         |
|   1. 装备精良的物理实验室攻击（开盖、FIB 聚焦离子束微探针分析）             |
|   2. 专业仪器施加的电压/激光/电磁故障注入（Fault Injection）               |
|   3. 高精度的差分功耗分析（DPA）与电磁侧信道攻击                           |
|   4. 拆焊 Flash 芯片后的重放回滚攻击（受限于 MCU 缺乏硬件防篡改单调计数器）|
+--------------------------------------------------------------------------+
```

---

## 四、 RS-Key 代码成熟度、工程治理与生态兼容性对比

### 1. 代码工程化治理与成熟度
RS-Key 虽然定位为实验性开源项目，但在软件工程和质量把控上展现了极高的工业级水准：

1. **测试体系金字塔**：
   - **Host 单元测试**：约 1500 个单元测试覆盖全套 APDU、CBOR、CTAPHID、TLV、密码学运算以及状态机。
   - **全面 Fuzzing（模糊测试）**：在 `fuzz/` 目录下维护了 **50+ 个独立的 `cargo-fuzz` 目标**（当前为 54 个），涵盖从外部 USB 数据流（APDU/CBOR/BER-TLV）、到所有 FIDO 命令、OpenPGP、PQC ML-DSA 解码、以及针对多步状态序列的有状态 Fuzzing（Stateful Fuzzing）。
   - **Miri 检查**：定期用 Miri 检测模糊测试用例中的未定义行为（Undefined Behavior）；这是检测手段，不覆盖逻辑错误或全部 `unsafe` 语义。
   - **Kani 形式化验证**：在关键数学归约、模运算和饱和计算部分编写了 `Kani` 模型检查证明（Bounded Model Checking）。
2. **CI/CD 与供应链安全**：
   - **可复现构建（Reproducible Builds）**：基于 Nix Flakes 锁定构建环境；同一平台（Linux 为 canonical）、同一 `flake.lock`、同一 commit 下可做到 bit-for-bit 一致。跨平台（macOS vs Linux）不保证一致。
   - **密码学签名与透明度**：Release 构建集成 Sigstore / Fulcio / Cosign 自动化无密钥签名，生成 CycloneDX SBOM 软件物料清单，并在 Rekor 公共透明日志中备案。
   - **静态审计与合规**：CI 流水线强制执行 `cargo clippy -D warnings`、`cargo audit`、`cargo deny`（强行封禁未授权的不安全依赖调用）和 `gitleaks`。

---

### 2. 客户端工具兼容性分析与支持矩阵

RS-Key 在主机端软件生态的适配能力表现非常出色：

| 客户端软件 / 工具链 | 兼容状态 | 实现细节与技术要点 |
| :--- | :---: | :--- |
| **YubiKey Manager (`ykman`)** | **可用**<br>(需特定预设) | 默认 RS-Key 采用自身 VID:PID (`1209:0001`)。使用 `VIDPID=Yubikey5`（`1050:0407`，reader 名含 "Yubico YubiKey"）时，`ykman piv/oath/otp info`、`ykman oath accounts` 等主要命令通过；不能据此说“所有配置项都完整验证”。另外该预设仅限本地互操作，禁止分发。 |
| **官方管理工具 (`rsk` / `rsk-tui`)** | **原生支持** | 官方基于 Python 开发了专属 CLI 工具 `rsk` 和终端界面工具 `rsk-tui`。支持查看设备详细硬件健康状态、导出/恢复 BIP-39 助记词、烧录安全启动与 OTP 熔丝、配置静态密码槽与 LED 参数。 |
| **图形化配置工具 (PicoForge)** | **第三方支持** | 来自 librekeys 项目的现代化跨平台 GUI 工具（基于 WebUSB/HID），能够直观管理 Passkeys、TOTP 槽位、PIV 证书、OpenPGP 状态、以及免编译修改板载 WS2812 LED 引脚与颜色映射。 |
| **主流 Web 浏览器 (Chrome/Firefox/Safari)** | **原生支持** | 支持全平台 WebAuthn 标准 API，支持 Passkey 登录注册（在 webauthn.io 测试全绿通过），解决了早期 pico-fido 在 Linux Firefox 上的解析兼容问题。 |
| **OpenSSH (`ssh-keygen`)** | **原生支持** | 原生支持 `ssh-keygen -t ed25519-sk` 与 `ecdsa-sk`，支持驻留密钥写入与免密码物理触控登录。 |
| **GnuPG (`gpg`)** | **原生支持** | 兼容 `gpg --card-status` 和 `gpg --edit-card generate`。早期版本的问题是 GET DATA **短 Le（256）+ 61xx 链式响应**导致密钥枚举失败，在固件 `0x075A` 修复。 |
| **OpenSC (`pkcs11-tool`)** | **原生支持** | 兼容 PKCS#11 模块加载，支持企业级智能卡身份验证与证书管理。 |
| **Yubico Authenticator (App)** | **原生支持** | 在 `VIDPID=Yubikey5` 镜像下，官方 Yubico Authenticator GUI 应用可正常搜索并管理 TOTP/HOTP 账号，点击即可触发计算。 |

---

## 五、 参考来源与边界说明

### 1. 参考来源

- RS-Key 仓库（`960b20a`；Release v0.4.11）：<https://github.com/TheMaxMur/RS-Key>
- 架构：<https://github.com/TheMaxMur/RS-Key/blob/main/docs/architecture.md>
- 威胁模型：<https://github.com/TheMaxMur/RS-Key/blob/main/docs/threat-model.md>
- 构建选项：<https://github.com/TheMaxMur/RS-Key/blob/main/docs/build.md>
- 生产/安全启动：<https://github.com/TheMaxMur/RS-Key/blob/main/docs/production.md>
- OTP fuse：<https://github.com/TheMaxMur/RS-Key/blob/main/docs/otp-fuses.md>
- Issue #37（Token2）：<https://github.com/TheMaxMur/RS-Key/issues/37>
- Token2 advisory：<https://github.com/user-attachments/files/30152894/T2-SA-RP2350-Dec2025.pdf>
- pico-fido 许可变更：<https://github.com/polhenarejos/pico-fido/commit/8b086188758ad3f60e912acd969b80d6801cfab3>
- pico-fido #129 / #245：<https://github.com/polhenarejos/pico-fido/issues/129>、<https://github.com/polhenarejos/pico-fido/issues/245>
- pico-fido2 README / ENTERPRISE：<https://github.com/polhenarejos/pico-fido2>
- RP2350 Hacking Challenge 结果：<https://www.raspberrypi.com/news/security-through-transparency-rp2350-hacking-challenge-results-are-in/>
- RP2350 A4 公告：<https://www.raspberrypi.com/news/rp2350-a4-rp2354-and-a-new-hacking-challenge/>
- PicoForge：<https://github.com/librekeys/picoforge>
- Web flasher：<https://rskey.fob.wtf/>

### 2. 边界说明

- 本文没有在真实 RP2350-Zero-CM 上刷写 RS-Key，也没有做功耗/故障注入实测；功能与物理表现以官方文档和源码为准，仍需在实际板卡上做板级确认。
- “A4 已含缓解”只针对 E16/E20/E21/E24；E17、E28、PVC/FIB 开盖读取和 PIN 回滚仍在防护边界外，不能据此宣称“抗实验室攻击”。
- RS-Key 是通用 MCU 方案，不是 SE；secure boot + OTP MKEK 能显著提高物理提取成本，但不提供 CC EAL6+ 级别的防篡改保证。
