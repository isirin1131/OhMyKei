# CanoKey-Core 软件架构与 RP2350 移植技术调研报告

**文档编号**：OHMYKEI-DOC-02  
**项目名称**：OhMyKei (基于 RP2350-Zero-CM 的开源硬件安全密钥)  
**更新日期**：2026-10-22  
**状态**：已修正（2026-10-22；以 canokey-core HEAD `abe8822` 为准复核）  

> ✅ **修订说明**：本文以 canokey-core HEAD `abe8822` 为准，并明确标注与 2025-02 旧快照的差异。已修正 PIN 存储、LittleFS 路径、NFC 接口、HAL 清单、参考 MCU 与代码体积等事实。

---

## 一、 canokey-core 软件架构解析

`canokey-core` 是开源安全密钥 CanoKey 的核心固件逻辑层，采用 C11 编写，平台无关，整体采用清晰的分层解耦设计：

```
+-----------------------------------------------------------------------------------+
|                                 Applets 应用层                                     |
|  +-------------+  +---------------+  +-------+  +--------+  +------+  +--------+  |
|  |  FIDO2/U2F  |  | OpenPGP Card  |  |  PIV  |  |  OATH  |  | NDEF |  | Admin/ |  |
|  |  (CTAP2.1)  |  |    (V3.4)     |  | (800) |  |TOTP/HOTP| |(NFC) |  | WebUSB |  |
|  +-------------+  +---------------+  +-------+  +--------+  +------+  +--------+  |
+-----------------------------------------------------------------------------------+
|                        APDU 分发与命令解析层 (apdu.c / ctap-parser.c)                |
+-----------------------------------------------------------------------------------+
|                        传输抽象层 (interfaces/USB & interfaces/NFC)                 |
|  +----------------+  +----------------+  +---------------+  +-------------------+ |
|  |  CTAPHID (HID) |  |   CCID 智能卡   |  | WebUSB(Vendor)|  | Keyboard HID(Pass)| |
|  +----------------+  +----------------+  +---------------+  +-------------------+ |
+-----------------------------------------------------------------------------------+
|           存储抽象 (fs.c -> LittleFS)   |    密码学引擎 (canokey-crypto)             |
|           Flash 损耗均衡 / 路径组织      |    tf-psa-crypto / ECC / RSA / 国密 / PQ  |
+-----------------------------------------------------------------------------------+
|                   硬件抽象层 HAL (include/device.h - 由宿主移植层实现)               |
+-----------------------------------------------------------------------------------+
```

### 1.1 支持的应用集（Applets）
1. **FIDO2 / CTAP2.1 与 U2F (CTAP1)** (`applets/ctap/`)：
   - **核心标准**：支持 FIDO 2.0 / 2.1 与 WebAuthn 标准，向下兼容 U2F 1.2。
   - **算法支持**：ES256 (ECDSA SECP256R1)、EdDSA (Ed25519) 等 COSE 签名算法。
   - **关键扩展**：
     - `hmac-secret` 扩展（基于 PRF，供 KeePassXC、Bitwarden、Windows Hello 派生对称密钥使用）。
     - `credProtect` 凭据保护扩展。
     - `largeBlobs` 大数据块存储。
   - **交互鉴权**：支持 PIN / UV（User Verification）密码协议与触摸用户在场证明（User Presence, UP）。
2. **OpenPGP Card V3.4** (`applets/openpgp/`)：
   - 实现智能卡 OpenPGP V3.4 规范。
   - 包含三套独立密钥槽：签名（Signature）、解密（Decryption）、认证（Authentication）。
   - 算法覆盖：RSA（2048/3072/4096 位）与 ECC（NIST P-256/P-384/P-521、Ed25519、X25519、secp256k1）。
   - 权限体系：User PIN (PW1)、Admin PIN (PW3)、Reset Code (RC)。
   - **PIN 存储方式**：CanoKey 把 PIN 明文存在 LittleFS 文件中，验证时直接 `memcmp`（`src/pin.c`），仅用文件属性保存重试计数器；OpenPGP 3.4 的 KDF（0xF9）未实现。PIN 的保密性依赖设备不被 dump，而不是存储层哈希。
3. **PIV (Personal Identity Verification)** (`applets/piv/`)：
   - 符合 NIST SP 800-73-4 标准。
   - 支持四大密钥槽：PIV Authentication (9A)、Digital Signature (9C)、Key Management (9D)、Card Authentication (9E)。
   - 支持 RSA 2048 与 ECC P-256/P-384，兼容 Windows 智能卡登录与 macOS 智能卡锁屏鉴权。
4. **OATH (TOTP / HOTP)** (`applets/oath/`)：
   - 兼容 RFC 6238 (TOTP) 与 RFC 4226 (HOTP)。
   - 支持 SHA-1、SHA-256、SHA-512 哈希，支持 6/8 位动态码与触摸确认输出。
   - 协议接口完全兼容 Yubico Authenticator 客户端。
5. **NDEF** (`applets/ndef/`)：
   - 符合 NFC Forum Type 4 Tag 规范，通过非接触接口对外暴露 URL/文本记录。
6. **Admin / WebUSB** (`applets/admin/`)：
   - 提供管理与固件配置 APDU，通过 WebUSB 直连官方管理网页（如 `console.canokeys.org`）。
   - 可对各个 Applet 进行独立启用/禁用、重置 PIN、配置触摸灵敏度与 LED 行为、执行工厂重置。
7. **Pass (Keyboard HID)** (`applets/pass/`)：
   - 静态密码/OTP 模拟键盘打字输出，长按触控区域即可自动将预设密码键入宿主主机。

### 1.2 传输层抽象
CanoKey 的传输层被设计为多协议端点复合设备：
- **CTAPHID (USB HID)**：单端点对（EP IN/OUT，通常 64 字节包长），传输 64 字节固定帧长结构（Init/Cont 帧），承载 FIDO2/WebAuthn 与 U2F 请求。
- **CCID (USB Class 0x0B)**：智能卡大容量传输端点（Bulk IN/OUT），负责承载遵循 ISO/IEC 7816-4 的扩展 APDU 数据，分发至 OpenPGP、PIV、OATH 及 Admin 应用。
- **WebUSB (USB Vendor Class)**：基于 Control Endpoint（EP0）的 Vendor 转移机制，结合 WebUSB BOS 描述符与 MS OS 2.0 描述符，无需安装驱动即可直接被 Chromium 系浏览器访问。
- **Keyboard HID**：标准的 USB Boot Keyboard 报告描述符，用于 Pass 功能模拟键盘击键。
- **NFC (Contactless)**：当前 HEAD 只支持 **FM11NT**（软件 bit-bang I2C），不支持 FM11NC，也没有 SPI 版本；`spi_transmit`/`spi_receive` 已从 `device.h` 移除。

### 1.3 文件系统与加密后端
- **文件系统**：采用 ARM 开源的 **LittleFS**。
  - **优势**：具有断电韧性（Power-loss Resilience）、内置损耗均衡（Wear Leveling）以及极小的 RAM 占用（仅需扇区级和页级缓冲区）。
  - **数据组织**：在 Flash 上以**扁平文件名**存储（不是目录树）：`ctap_dc` 等存放 Resident Keys 与计数器；`pgp-data` 存放 OpenPGP 三大密钥元数据与私钥材料；`piv-chu` 存放 PIV 证书与容器；`oath` 存放 TOTP 种子；`pass` 存放静态密码。做迁移/备份/擦除时不要按 `/fido/...`、`/openpgp/...` 这类目录去处理。
- **加密后端（`canokey-crypto`）**：
  - 基于 `tf-psa-crypto`（TrustedFirmware PSA Crypto / Mbed TLS 的现代独立加密分支）及深度优化的软件算法库。
  - **公钥算法**：
    - 短维尔斯特拉斯曲线（Short Weierstrass）：NIST P-256、P-384、P-521、secp256k1 以及国产国密 **SM2**。
    - 蒙哥马利/爱德华曲线（Montgomery/Edwards）：**Ed25519** 签名与 **X25519** 密钥协商。
    - RSA：2048、3072、4096 位的密钥生成、CRT 私钥运算、PKCS#1 v1.5 与 PSS 填充。
    - **后量子算法（PQC）**：已率先实验性集成 NIST 后量子标准 **ML-KEM-512/768** 与 **ML-DSA-44/65**。
  - **对称与摘要算法**：AES-128/192/256、Triple DES (TDEA)、SHA-1/224/256/384/512、SHA-3、Keccak-p1600、SM3、HMAC。

---

## 二、 移植接口（Porting Interface / HAL）深度剖析

`canokey-core` 保持平台无关的核心原则是：核心库只负责协议编解码与状态机演进，所有硬件相关操作全部通过 `include/device.h` 及文件系统/USB 回调委托给硬件移植工程。

### 2.1 `include/device.h` 要求宿主实现的接口（HEAD `abe8822`）

当前 canokey-core 的移植接口分为三类，不能把“core 自带的函数”误列为宿主职责：

**（1）宿主必须实现（`include/device.h`）**：

```c
/* 基础时基与延时 */
void device_delay(int ms);              // 阻塞延时；期间应泵送 USB 任务或让出控制权
uint32_t device_get_tick(void);         // 自开机以来的毫秒单调计数

/* 并发与同步 */
int device_spinlock_lock(volatile uint32_t *lock, uint32_t blocking);
void device_spinlock_unlock(volatile uint32_t *lock);
int device_atomic_compare_and_swap(volatile uint32_t *var, uint32_t expect, uint32_t update);

/* 指示灯与定时器 */
void led_on(void);
void led_off(void);
void device_set_timeout(void (*callback)(void), uint16_t timeout); // 毫秒级单次超时回调

/* NFC：FM11NT 走软件 I2C；没有 NFC 时也必须提供空实现 */
void fm_csn_low(void);
void fm_csn_high(void);
#if NFC_CHIP == NFC_CHIP_FM11NT
void i2c_start(void);
void i2c_stop(void);
void i2c_bus_recover(void);
void scl_delay(void);
fm_status_t i2c_read_ack(void);
void i2c_send_ack(void);
void i2c_send_nack(void);
fm_status_t i2c_write_byte(uint8_t data);
uint8_t i2c_read_byte(void);
#endif
```

**（2）由其他头文件要求、但同样属于平台层**：

- `random32()` / `random_buffer()`：来自 `canokey-crypto/include/rand.h`，必须在平台层提供密码学安全的随机源；
- `USBD_LL_*`：如果跟随当前 HEAD 的 vendored ST USB 栈，需要实现约 25 个底层 USB 回调；如果钉住旧的 TinyUSB 分支，则改为实现 TinyUSB 的 `tud_*` 回调。这两条路只能选一条，详见 2.3。

**（3）core 已提供，宿主不要重复实现**：

`device_init()`、`device_loop()`、`wait_for_user_presence()`、`get_touch_result()` / `set_touch_result()`、`device_update_led()`、`start_blinking()` / `stop_blinking()`、`device_is_blinking()`、`device_allow_kbd_touch()` 等都在 `src/device.c` 中实现；宿主只需在主循环调用 `device_loop()`，并在按键扫描时注入 `set_touch_result()`。

> **版本差异**：2025-02 的旧快照曾使用 TinyUSB + FM11NC over SPI，`device.h` 里有 `spi_transmit()` / `spi_receive()`；当前 HEAD 已移除这两个函数和 FM11NC 支持。`WorkingWarrior/canokey-core` 的 `pico2` 分支基于 2024-06 的旧 core，若钉住该分支，请以它的 `device.h` 为准，不要混用本文的 HEAD 清单。

#### 平台无关但由核心依赖的触控调度机制
在 `src/device.c` 中，核心库实现了平台无关的触控状态机：
- `uint8_t wait_for_user_presence(uint8_t entry)`：当 FIDO 或 OpenPGP 需要物理在场证明时调用此函数。它会进入持续 30 秒的事件循环，期间调用 `start_blinking(0)` 保持闪烁、`CTAPHID_Loop(1)` 处理取消帧、每 100ms 发送 `CTAPHID_SendKeepAlive(KEEPALIVE_STATUS_UPNEEDED)`，直到检测到 `get_touch_result() != TOUCH_NO`。
- 宿主需要通过周期性定时器（如每 10ms）或中断，将物理按键/电容触摸扫描的结果通过 `set_touch_result(TOUCH_SHORT / TOUCH_LONG)` 注入核心。

### 2.2 Flash 读写与擦除接口适配 LittleFS
`canokey-core/src/fs.c` 定义了全局的 `lfs_t lfs`，并通过 `fs_mount(const struct lfs_config *cfg)` 接收配置。宿主需要填充 `struct lfs_config`，把下面四个回调分别赋给 `.read`、`.prog`、`.erase`、`.sync` 字段（函数名可自取）：

```c
static int flash_read(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, void *buffer, lfs_size_t size);
static int flash_prog(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, const void *buffer, lfs_size_t size);
static int flash_erase(const struct lfs_config *c, lfs_block_t block);
static int flash_sync(const struct lfs_config *c);
```

#### RP2350 适配的关键细节：
1. **地址空间与对齐**：
   - RP2350 外挂 QSPI NOR Flash（标准 2MB 起步，扇区 Sector 大小 4096 字节，编程页 Page 大小 256 字节）。
   - LittleFS 分区一般放置在 Flash 末尾（如保留高地址 256KB~1MB）。
   - 读操作可直接通过内存映射指针完成：`memcpy(buffer, (uint8_t *)(XIP_NOCACHE_NOALLOC_BASE + addr), size)`。
2. **XIP 冲突与中断安全性**：
   - **核心痛点**：在 RP2350 执行 Flash 擦除或编程时，QSPI 总线必须切换为擦写指令，此时 CPU 无法从 Flash 取指（XIP 挂起）。
   - **保护要求**：必须在擦写期间关闭中断（`save_and_disable_interrupts()`），且如果启用了 Dual-Core（双核），必须调用 Pico SDK 提供的 `flash_safe_execute` 或 `multicore_lockout` 将另一核也锁定在 RAM 中，否则将发生 HardFault 总线锁死。

### 2.3 USB 协议栈对接：TinyUSB 与 CanoKey 消息循环
`canokey-core` 在 **2025 年的快照**里曾使用 TinyUSB；当前 HEAD 又回到了 vendored ST USB device stack（`USBD_HandleTypeDef`）。因此下面这套 TinyUSB 对接方案**只适用于钉住旧提交或 `WorkingWarrior/canokey-core` 的 `pico2`/`feature/tinyusb` 分支**，不是当前 upstream 的现成接口。

如果你选择跟当前 HEAD，需要自己写 `USBD_LL_*`（25 个函数）到 TinyUSB 的适配层，工作量明显更大；如果选择旧分支，则要接受它与 2024-06 之后的上游修复脱节。

1. **复合设备接口配置（`tusb_config.h`）**：
   - 声明启用复合设备：
     ```c
     #define CFG_TUD_HID     2   // 实例 0 为 CTAPHID，实例 1 为 Keyboard HID
     #define CFG_TUD_CCID    1   // 智能卡 CCID 接口
     #define CFG_TUD_VENDOR  1   // WebUSB 控制传输
     ```
2. **数据交互与回调分发**：
   - **CCID 管道**：
     - Host -> Device：TinyUSB 接收到 CCID Bulk-Out 包后，触发 `tud_ccid_rx_cb`，调用 `CCID_OutEvent(len)` 组装 APDU。
     - Device -> Host：APDU 执行完毕后，调用 `CCID_Response_SendData()` -> `tud_ccid_write()` 发送 RDR_to_PC_DataBlock。长时间运算（如 RSA-4096）时，由 `CCID_TimeExtensionLoop` 周期性发送 WTX（Wait Time Extension）帧防止主机驱动报超时（0x8010002F）。
   - **CTAPHID 管道**：
     - TinyUSB 触发 `tud_hid_set_report_cb`（分发到 `ctap_hid_set_report_cb`），复制 64 字节 CTAPHID 报文并置位 `has_frame`。
     - 主循环轮询 `CTAPHID_Loop(0)`，解析 CBOR / MSG 报文，调用 `ctap_install()` 或对应密码学处理，再通过 `tud_hid_n_report` 异步回送。
   - **WebUSB 管道**：
     - 在 `tud_vendor_control_xfer_cb` 中响应 WebUSB BOS 描述符与 MS OS 2.0 描述符，并在接口控制传输阶段把 APDU 读写入全局缓冲区。
3. **主任务驱动模型**：
   - 主循环保持极低延迟轮询：
     ```c
     while (1) {
         tud_task();        // 驱动 TinyUSB 协议栈
         device_loop();     // 驱动 CCID_Loop(), CTAPHID_Loop(), WebUSB_Loop(), KBDHID_Loop()
     }
     ```

---

## 三、 许可证与法律边界分析

### 3.1 Apache 2.0 许可证条款特征
`canokey-core` 和 `canokey-crypto` 采用 **Apache License 2.0** 许可证。该许可证虽然属于宽松型（Permissive）开源协议，但相比极简的 MIT 协议，具备更严格的法律约束和要求：
1. **保留版权与许可声明（Section 4.a）**：再分发形式无论是源码还是二进制，都必须包含 Apache 2.0 原始许可文本以及原始版权所有者的版权声明。
2. **显著修改声明（Section 4.b）**：任何被修改过的文件，必须在文件头部或显著位置声明该文件已被修改（"prominent notices stating that you changed the files"）。
3. **NOTICE 文件继承（Section 4.d）**：如果原项目中包含 `NOTICE` 文本文件，分发的衍生版本必须在分发包或关于界面中完整保留该 NOTICE 文件的内容。
4. **明确的专利授权与终止（Section 3）**：授予代码用户永久的、全球性的、非排他的专利许可；若使用者向该项目发起专利侵权诉讼，其专利许可即刻终止。

### 3.2 对 OhMyKei（当前为 MIT 协议）的法律约束与推荐策略
- **冲突焦点**：MIT 协议不能直接“吞并”并把 Apache 2.0 的源代码强行变更为 MIT。如果 OhMyKei 采用 Git Submodule 或直接复制编译 `canokey-core`，**整个编译产物或项目在法律上必须满足 Apache 2.0 的全部合规条件**。
- **推荐合规实施方案**：
  1. **方案 A（双协议声明 - 推荐，业界标准做法，如 Rust 生态）**：
     将 OhMyKei 的顶级许可证升级为 **MIT OR Apache-2.0**（双重授权模式）。这样既保留了 MIT 的自由度，又与上游 Apache 2.0 的专利/归属要求保持完全兼容。
  2. **方案 B（模块隔离模式）**：
     若 OhMyKei 顶级仓库仍希望维持纯 MIT 协议：
     - 必须将 `canokey-core` 严格作为 Git Submodule 引入，保持其内部原始目录、`LICENSE`、`NOTICE` 文件以及文件头部 `SPDX-License-Identifier: Apache-2.0` 原封不动。
     - 在 OhMyKei 顶级 `README.md` 与分发文档中增加第三方代码声明（Third-Party Licenses），明确指出：“Core security key logic is derived from canokey-core, licensed under the Apache License 2.0”。
     - 宿主移植层（OhMyKei 自研的 RP2350 HAL 与适配代码）可以单独使用 MIT 许可证。

---

## 四、 资源占用与 RP2350 适配现状

### 4.1 Cortex-M 平台上的 Flash 与 RAM 资源占用
CanoKey 的参考硬件是 **STM32L432KC**（Cortex-M4，256KB Flash / 64KB RAM）。其链接脚本把应用区限制在 **190KB**、LittleFS 66KB（`0x08000000` 起 190K，`0x0802F800` 起 66K），因此“320KB 固件”在参考硬件上不可能。RP2350 的空间更宽裕是事实，但具体占用应在目标板上重新测量，不要沿用 180–320KB 的旧区间。

| 资源项 | CanoKey 参考实现的约束 | RP2350-Zero-CM 硬件规格 | 空间充裕度 / 评估 |
| :--- | :--- | :--- | :--- |
| **Code Flash (固件体积)** | 链接脚本上限 **190KB**（app）+ 66KB（LFS）；RP2350 上未实测 | **2MB (外挂 QSPI Flash)** | **宽裕**，但不要把 320KB 当成已验证数字 |
| **SRAM (静态 + 运行堆栈)** | 参考实现约 64KB；RP2350 上需用 `arm-none-eabi-size` + 栈水位实测 | **520KB SRAM (10 个独立 Bank)** | 大概率宽裕，但仍应保留栈保护/水位测试 |

> **空间对比优势**：在商业 YubiKey 或 STM32 方案中，受限于 Flash 空间，往往需要裁剪 RSA-4096 或限制 Resident Keys 数量。RP2350 的 2MB Flash 确实给了更大余量；但“数千个 Discoverable Credentials”还受 applet 的实现上限、LittleFS 元数据开销与检索策略影响，不能只按字节数推算，建议做一次容量实测。

### 4.2 社区移植现状剖析（以 WorkingWarrior/canokey-pico2 为例）
开源社区开发者 `WorkingWarrior` 已经尝试将 CanoKey 移植到了 Raspberry Pi Pico 2（RP2350）：
- **实现路径**：
  1. Fork 了 `canokey-core`，并在 fork 中维护 `pico2` / `feature/tinyusb` 分支（`canokey-pico2` 主仓库本身只有 `master`），把 ST USB Device 驱动重构为 TinyUSB。
  2. 使用 Pico SDK 2.x，通过 `lfs_pico_flash_config` 将 Flash 末尾 256KB（`FS_SIZE = 0x40000`）映射为 LittleFS。
  3. **BOOTSEL 读取有坑**：该分支自己写了一个 `get_bootsel_button()`，但用的是 `sio_hw->gpio_hi_in & (1u << 1)`；RP2350 的 QSPI_CSN 实际在 **bit 27**（`SIO_GPIO_HI_IN_QSPI_CSN_BITS = 0x08000000`）。这段代码在 RP2350 上读的不是 BOOT 键，**不要照抄**；应使用 `SIO_GPIO_HI_IN_QSPI_CSN_BITS` 或 `flash_safe_execute()` 包装。
  4. 截取 RP2350 唯一的 64 位芯片 ID（`pico_get_unique_board_id()`）作为 **admin 硬件序列号**（用于管理命令），不是 USB 序列号，也不是 FIDO AAGUID。
- **现状与严重局限性**：
  1. **无静态加密（明文存储）**：
     - LittleFS 直接写入外部 SPI Flash，数据完全未加密。任何具有物理接触条件的人通过 SWD 调试器或 `picotool` 即可将 Flash 完全导出，窃取全部私钥（OpenPGP/FIDO Master Secret）。
  2. **Flash 擦写并发隐患**：
     - 在 `src/lfs_init.c` 中，仅调用了 `save_and_disable_interrupts()` 便执行 `flash_range_program`。这没有调用 Pico SDK 规范的 `flash_safe_execute()`，且一旦引入 Core 1 多核，将直接导致系统崩溃。
  3. **未合并入官方 Upstream**：
     - 该工程修改侵入了 `canokey-core` 内部（维护在个人 fork 分支），代码与 upstream 存在脱节风险。
  4. **基本未利用 RP2350 的硬件安全特性**：
     - 没有 TrustZone 隔离：整个固件运行在 Secure 态，没有 Non-Secure world；
     - 未使用 RP2350 内部 OTP 存储根密钥（Root Key）；
     - 未调用 RP2350 片上硬件 SHA-256 加速器，全部使用软件计算（mbedtls 配置为默认软件实现）；
     - 未做多核隔离（Core 1 彻底闲置，所有计算挤在 Core 0）。

---

## 五、 canokey-core 在 RP2350 上移植的优劣势总结与建议

### 5.1 优势（Pros）
1. **多应用生态高度成熟**：CanoKey 在单一固件内较完整地融合了 FIDO2/WebAuthn、OpenPGP、PIV 与 OATH，且经过多年实际使用，是目前开源界功能最完备的实现之一。
2. **软硬件架构极佳解耦**：核心状态机完全不感知底层芯片型号，仅依靠简单的 `device.h` 和 LittleFS 函数即可完整驱动。
3. **RP2350 算力与内存压倒性过剩**：
   - 150MHz Cortex-M33 主频 + 硬件浮点/DSP 指令集，使常见密码学操作（如 Ed25519、RSA-2048 签名）通常达到毫秒级；具体延迟需实测。
   - 520KB SRAM 大幅降低嵌入式加解密的栈溢出风险，但深栈路径（RSA/ML-DSA）仍需栈水位测试。
   - 2MB 以上 Flash 为未来支持 PQC（ML-KEM/ML-DSA）提供了前瞻性的物理空间。

### 5.2 劣势与挑战（Cons）
1. **缺乏专用硬件安全单元（Secure Element, SE）**：
   - STM32 或标准商业 Key 常配有防探针、防侧信道攻击的 SE 芯片。RP2350 是通用 MCU，但比 RP2040 多了 OTP、secure boot、encrypted boot（解密到 SRAM，不是透明 XIP 加密）和 glitch detector 等能力；这些需要 OhMyKei 从系统层组合激活，且不能替代 SE 的物理防护。
2. **Flash 运行时写入的 XIP 冻结瓶颈**：
   - 安全密钥每注册一个凭据或计数器累加，都需要写 Flash。必须严密处理 Flash 写入期间 USB 中断延迟与总线冻结的问题。
3. **触控与防抖**：
   - RP2350 没有硬件触摸外设（TSC），若要实现纯触控金属片，必须像 `canokey-stm32` 那样采用 GPIO 充放电 RC 计时软件算法，或者外接独立电容触控芯片/物理按键。

---

### 5.3 对 OhMyKei 项目的落地方案建议

```
+-------------------------------------------------------------------------------+
|                       OhMyKei 推荐双核与安全架构规划                          |
|                                                                               |
|  [ Core 0: 通信与调度核心 ]                   [ Core 1: 安全与密码学核心 ]     |
|  * USB Device 栈 (CCID/HID/WebUSB)           * tf-psa-crypto 加密运算引擎     |
|  * APDU/CTAP 命令解析与分发                    * RSA-4096 / ECC / PQC 私钥运算  |
|  * LED 灯效驱动 & 电容触控扫描                 * OTP 硬件主密钥派生与鉴权        |
|  * LittleFS 安全缓存层                        * Flash 静态加密层（固件实现）    |
|                     <==== 进程间通信 FIFO / 门铃 ====>                        |
+-------------------------------------------------------------------------------+
|                                  底层安全保障                                 |
|  * RP2350 Secure Boot (签名固件验证)                                         |
|  * OTP Key-Store (不可导出的设备主种子)                                        |
|  * flash_safe_execute (保护 QSPI 擦写过程)                                    |
+-------------------------------------------------------------------------------+
```

1. **吸纳 WorkingWarrior 的 TinyUSB 适配思路，但先决定钉住哪个 core 版本**：
   - 若用 TinyUSB，必须钉住 2024-06 的旧 core（或 fork 的 `pico2` 分支）；若跟当前 HEAD，则要写 ST `USBD_LL_*` 适配层。两条路的胶水都放在 OhMyKei 自己的适配层，不要直接改 `canokey-core` 源码。
2. **利用 RP2350 OTP 解决数据防提取问题（存储加密）**：
   - 利用 RP2350 OTP 中的唯一随机私钥作为 KEK（Key Encryption Key），在 LittleFS 驱动底层透明增加 AES-XTS / ChaCha20-Poly1305 加密层，使得即使通过外部读取 Flash，提取出的所有凭据和私钥也全为密文。
3. **利用双核（Dual-Core）并发消解计算延迟**：
   - Core 0 专心处理 USB 接收、触控检测和心跳 KeepAlive 发送，显著降低 RSA-4096 耗时计算导致的 USB 掉线或无响应风险。
   - Core 1 专职负责耗时的加解密运算。
4. **许可证合规落地**：
   - 采纳 **MIT OR Apache-2.0** 双协议，保证合规且最大化回馈开源社区。
