# 微雪（Waveshare）RP2350-Zero-CM 硬件规格与固件构建最佳实践技术调研报告

**文档编号**：OHMYKEI-DOC-01  
**项目名称**：OhMyKei (基于 RP2350-Zero-CM 的开源硬件安全密钥)  
**更新日期**：2026-10-22  
**状态**：已修正（2026-10-22；依据微雪原理图、RP2350 数据手册与 picotool 2.3.1 复核）  

> ✅ **修订说明**：本文的硬件事实已对照微雪原理图与 RP2350 数据手册核对；构建、签名与分区表章节已按 picotool 2.3.1 的实际行为修正。

---

## 一、 硬件规格与接口特性深度剖析

### 1. 核心芯片与存储架构
* **主控芯片型号**：**Raspberry Pi RP2350A**（微雪原理图 U2 标注 **`RP2350A0A4`**，即 A4 步进；实物以封装 marking 为准）
  * **封装规格**：**QFN-60**（7×7 mm 紧凑封装）。
  * **引脚数量**：60 个物理引脚 + 底部裸露接地焊盘（Pad 61 GND）。RP2350A 芯片提供 30 个 GPIO（GPIO 0 ~ GPIO 29），区别于 80 脚 QFN-80 封装的 RP2350B（引出 48 个 GPIO）。**注意：RP2350-Zero-CM 只引出了 29 个 GPIO**，GPIO16 被板载 WS2812B 占用，不在可焊接/排针引脚中。
* **板载 Flash 容量（关键事实与避坑点）**：
  * **标称容量**：**2MB (16Mbit) NOR Flash**（产品页与原理图 BOM 一致；非本文实测）。
  * **芯片型号**：**Winbond（华邦）W25Q16JVUXIQ**，采用 USON-8 (2×3 mm) 超微型封装。
  * **总线模式**：专用高速 QSPI 接口（`QSPI_SS`, `QSPI_SCLK`, `QSPI_SD0~SD3`），最高支持 133MHz+ 运行并执行 XIP（Execute-In-Place）就地代码执行。
  * ⚠️ **特别注意事项**：标准微雪 RP2350-Zero 搭载 4MB Flash，而 **RP2350-Zero-CM 搭载 2MB Flash**。固件构建与链接脚本配置中必须显式覆盖 Flash 边界，严禁直接照搬 4MB/16MB 配置，否则会导致存储数据越界并触发回环覆盖。
* **片上 SRAM**：
  * **520KB**，划分为 10 个独立 Bank（SRAM0~7 各 64KB，以及 2 个 4KB Scratch Bank）。
  * 支持 Crossbar 总线矩阵，双核 CPU、DMA 与 USB 控制器可并发全速访问无冲突。
* **PSRAM（伪静态随机存储器）**：
  * **无板载 PSRAM**。RP2350-Zero-CM 为极限微型化设计，未预留外置 PSRAM 芯片。由于 520KB SRAM 完全足以驻留 FIDO2/WebAuthn 协议栈、USB 描述符缓冲区及密码学工作上下文，无需外扩 PSRAM。

---

### 2. 物理接口与板载外设

| 外设 / 接口 | 原理图代号 / 引脚 | 特性与设计细节 |
| :--- | :--- | :--- |
| **USB 接口** | `Type_C` (Male 公头) | **Type-C 插件公头 (CM = Type-C Male)**，可直接插入电脑/手机 Type-C 端口，免除线缆，天然适合安全硬件 Key 外形。具备 ESD5451 等静电防护器件。 |
| **RGB 指示灯** | `L2: WS2812B` | 信号控制线连接至 **GPIO 16**，电源端连至 **3V3**（原理图 L2 的 VDD 网络为 3V3，不是 VBUS）。通过 RP2350 的 PIO 状态机输出单总线 NRZ 800kHz 驱动时序。透光外壳下可作为状态灯（待机呼吸、等待触摸闪烁、认证成功绿色等）。注意 WS2812B 的标准字节序是 **GRB**，而 RS-Key 默认 `LED_ORDER=rgb`；首次刷写可能红绿互换。 |
| **BOOT 按键** | `Key1: BOOT` | 串联 1kΩ 限流电阻（`R6`）连接到 Flash 片选引脚 **`QSPI_SS`**。复位/上电时按下，QSPI 片选被拉低，强制芯片进入 BootROM USB 磁盘下载模式。 |
| **RUN 按键** | `Key2: RUN` | 连接至 RP2350 的物理复位引脚 **`RUN`（Pin 26）**，按下时通过下拉对地复位整个 MCU。 |
| **调试接口** | `SWD` (J2) | 预留背面调试焊点：`SWCLK` (Pin 24)、`SWDIO` (Pin 25)、`GND`，便于离线烧录与 SWD 硬件仿真。 |
| **LDO 稳压** | `U3: ME6217C33M5G` | SOT-23-5 低压降 LDO，最大输出电流 800mA，将 VBUS 5V 转换为稳定 3.3V 供应 IOVDD 与 Flash。片内开关 DC-DC（搭配外部 3.3μH 电感 `L1`）产生 1.1V 供应核心内核电压。 |

---

### 3. 外壳安装状态下 BOOT 键作为安全密钥在场证明（UP）的底层实现

在 3D 打印卡扣外壳下，BOOT 键外露活动按键帽，是用户在场证明（User Presence, UP / Touch Confirm）最直接的物理输入媒介。

#### 核心挑战
`BOOT` 键在电气上**并不是一个独立的 GPIO**，而是挂接在 SPI Flash 的 **`QSPI_SS`（片选线）** 上。
MCU 正常运行时正通过 XIP 引擎不断从 Flash 读取指令。如果在执行 Flash 代码时直接操作 QSPI 片选或机械按键下拉，会导致指令预取中断、总线挂起（BusFault）甚至系统崩溃。

#### 固件中安全采样 BOOTSEL 的完整方案与代码
在 Pico SDK 2.x 中，安全读取 BOOTSEL 必须满足以下四个铁律：
1. **代码与中断必须驻留 SRAM**：读取函数必须被 `__no_inline_not_in_flash_func()` 显式修饰；
2. **关闭全局中断**：防止采样期间触发中断向量读取 Flash；
3. **多核互斥挂起（Multicore Lockout）**：若 Core 1 处于活跃状态，必须锁定暂停 Core 1，避免 Core 1 在 XIP 期间发生 Cache Miss；
4. **RP2350 专有寄存器位处理**：RP2350 的 QSPI 状态寄存器位定义为 `SIO_GPIO_HI_IN_QSPI_CSN_BITS`（区别于 RP2040 的 `1u << 1`）。

**标准可靠实现代码**：

```c
#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/sync.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/sio.h"
#include "pico/multicore.h"

/**
 * @brief 在运行态安全读取 BOOTSEL 按键状态（作为 FIDO2 User Presence 判定）
 * @return true 按键被按下; false 按键释放
 */
bool __no_inline_not_in_flash_func(read_user_presence_bootsel)(void) {
    const uint CS_PIN_INDEX = 1; // QSPI SS 索引

    // 1. 如果使用了多核，先锁定挂起 Core 1，禁止其在此期间访问 XIP Flash
    //    注意：PICO_CORE1_ENABLED 不是 SDK 宏；正确条件是链接了 pico_multicore
    //    （LIB_PICO_MULTICORE），且 Core 1 必须已调用 multicore_lockout_victim_init()。
#if LIB_PICO_MULTICORE
    multicore_lockout_start_blocking();
#endif

    // 2. 关中断并保存中断状态
    uint32_t interrupts_status = save_and_disable_interrupts();

    // 3. 将 QSPI CS 引脚临时切换为高阻态（Hi-Z / 浮空输入）
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    // 4. 极短暂延时（busy-wait），让线路充放电稳定（不可调用 flash 内的 sleep 函数）
    for (volatile int i = 0; i < 1500; ++i) {
        __asm volatile("nop");
    }

    // 5. 读取 SIO 寄存器状态：按键按下时 QSPI_SS 被拉低为 0
#if PICO_RP2040
    #define BOOTSEL_CS_BIT (1u << 1)
#else
    // RP2350 架构专用定义
    #define BOOTSEL_CS_BIT SIO_GPIO_HI_IN_QSPI_CSN_BITS
#endif
    bool is_pressed = !(sio_hw->gpio_hi_in & BOOTSEL_CS_BIT);

    // 6. 恢复 QSPI CS 片选为正常控制器驱动模式
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    // 7. 恢复中断
    restore_interrupts(interrupts_status);

    // 8. 解除多核锁定
#if LIB_PICO_MULTICORE
    multicore_lockout_end_blocking();
#endif

    return is_pressed;
}
```

> **复核补充**：`get_bootsel_button()` 并非 pico-sdk 的 API，而是 `pico-examples/picoboard/button/button.c` 中的示例；SDK 本身只提供 `flash_safe_execute()`。如果 Core 1 正在运行，必须在 Core 1 启动时调用 `flash_safe_execute_core_init()`（等价于 `multicore_lockout_victim_init()`），否则 `multicore_lockout_start_blocking()` 会永久等待。更稳妥的写法是把采样函数交给 `flash_safe_execute()`，由 SDK 统一完成“锁另一核 + 关中断”。另外，RP2350 的 QSPI_CSN 在 `SIO_GPIO_HI_IN` 的 bit 27（`SIO_GPIO_HI_IN_QSPI_CSN_BITS = 0x08000000`），不是 RP2040 的 bit 1；网上部分 RP2350 移植代码（如 `canokey-pico2`）误用了 `1u << 1`，不要照抄。

---

## 二、 固件构建最佳实践

### 1. Pico SDK 2.x 的 CMake 配置与 2MB Flash 边界防护

> **项目抉择更新（2026-10-26）**：OhMyKei 曾短暂采用 Meson + Ninja，并用约 500 行 Meson 桥接手工复刻 `pico-sdk` 的 defines/includes/sources；该方案会随 SDK 升级静默漂移，且无 SDK 时的 Wrap fallback 不可用。现正式回到 **CMake + Ninja**：固件直接使用官方 `pico_sdk_init()`，Host 测试与 Fuzz 走同一工程的 `host` / `fuzz` preset。构建入口见根目录 `CMakeLists.txt` 与 `CMakePresets.json`。

#### 避坑指南：板级定义与 Flash 大小
Pico SDK 2.x 提供了 `waveshare_rp2350_zero` 的板级定义，但在该定义中微雪默认配置为 4MB（`PICO_FLASH_SIZE_BYTES = 4 * 1024 * 1024`）。
**RP2350-Zero-CM 实际 Flash 为 2MB**！若不显式覆盖，会导致：
* LittleFS 文件系统或非易失数据区被放置在 `2MB ~ 4MB` 虚假地址，写入时在 2MB 内发生**地址回环覆写（Wrap-around）**，破坏自身固件代码；
* 启动时校验失败，出现 Bootloop 死循环。

#### OhMyKei 实际采用的构建方案：CMake presets
* 板级头与彩灯驱动：直接复用 `pico-sdk` 2.3.1 内置的 `boards/waveshare_rp2350_zero.h` 与 `pico_status_led`（`pico/status_led.h`）。CM 版与标准 Zero 的片上差异只有 Flash 大小（2MB vs 4MB），因此不需要项目板级头：在 target 上调用 `pico_override_flash_size(ohmykei 2097152)` 即可生成 2MB 链接区域并注入整数编译宏；`main.c` 里的 `_Static_assert(PICO_FLASH_SIZE_BYTES == 2097152, ...)` 兜底防止覆盖丢失。
* SDK 的 `version.h`、`config_autogen.h`、`pico_flash_region.ld` 与 `uf2`/`bin`/`hex`/`dis`/`map` 全部由 `pico_sdk_init()` / `pico_add_extra_outputs()` 生成，项目不再手写任何 SDK 源文件列表或链接脚本。
* 构建与烧录命令：
  ```bash
  cmake --preset fw-release
  cmake --build --preset fw-release
  cmake --build --preset fw-release --target flash
  # 或 picotool load -f -x build/fw-release/ohmykei.uf2
  ```
* Host 测试与 Fuzz：
  ```bash
  cmake --preset host && cmake --build --preset host && ctest --preset host
  cmake --preset fuzz && cmake --build --preset fuzz && ctest --preset fuzz
  ```

#### 构建配置要点（与根目录 `CMakeLists.txt` 一致）
```cmake
cmake_minimum_required(VERSION 3.25)

set(PICO_BOARD waveshare_rp2350_zero CACHE STRING "")
include(cmake/pico_sdk.cmake)

project(ohmykei C CXX ASM)
pico_sdk_init()

set(OMK_FIRMWARE_SOURCES src/main.c src/platform/bootsel.c)
add_executable(ohmykei ${OMK_FIRMWARE_SOURCES})
target_include_directories(ohmykei PRIVATE src)

# CM 版与标准 Zero 的唯一片上差异：2MB 而不是 4MB Flash。
pico_override_flash_size(ohmykei 2097152)

# 严格 flag 只作用于项目源码；SDK 源码会一起编进同一个 target。
set_source_files_properties(${OMK_FIRMWARE_SOURCES}
    PROPERTIES COMPILE_OPTIONS "-std=c17;-Wall;-Wextra;-Werror")

target_link_libraries(ohmykei PRIVATE pico_stdlib pico_status_led)
pico_enable_stdio_usb(ohmykei 1)
pico_enable_stdio_uart(ohmykei 0)
pico_add_extra_outputs(ohmykei)
```

> **板级定义补充**：pico-sdk 2.3.1 没有 `waveshare_rp2350_zero_cm` 板级头，因为 CM 与标准 Zero 的片上差异只有 Flash 大小。直接使用官方 `waveshare_rp2350_zero.h`，并用 `pico_override_flash_size(ohmykei 2097152)` 覆盖即可；不要复制或改写 SDK 板级头，否则会引入无意义的维护分叉。
> `pico_override_flash_size()` 会给 target 注入整数宏 `PICO_FLASH_SIZE_BYTES=2097152`，`main.c` 的 `_Static_assert` 保证它没有被漏掉。
> 另外，`pico_enable_stdio_usb(ohmykei 1)` 会给安全密钥额外加一个 CDC 串口与 `picotool` 复位接口；研发阶段开启可实现免按键 `picotool load -f -x` 重刷，正式复合 HID/CCID 阶段再关闭。

#### 工具链要求（GCC 版本说明）
* **推荐**使用 pico-sdk 2.3.x 官方验证过的 **ARM GNU Toolchain 14.2 / 15.3**（或 13.2）。**GCC 13 不是硬性下限**：pico-sdk 2.3.1 自身没有版本检查，其 CI 仍可用 arm-none-eabi-gcc 9.2.1 构建 RP2350。
* **纠正三个常见误解**：
  1. `-mcmse` 不需要你手动加，也不依赖 GCC 13；pico-sdk 的 `pico_arm_cortex_m33_gcc.cmake` 在 `NOT PICO_NO_CMSE` 时会自动加。
  2. **PAC/BTI 与 RP2350 无关**：它们是 Armv8.1-M 的扩展，而 RP2350 的 Cortex-M33 是 Armv8-M。GCC 在 armv8-m 上会把这些选项降级为 NOP 空间，“能编译”不等于硬件支持。
  3. DSP 与硬件除法是 `armv8-m.main` 的基线能力，SDK 的 `-march=armv8-m.main+fp+dsp` 已包含，不需要靠新 GCC 获得。

---

### 2. RP2350 架构与硬件安全特性利用

#### (1) Cortex-M33 双核 vs Hazard3 RISC-V 选型
* **结论**：**OhMyKei 安全密钥项目必须使用 Arm Cortex-M33 架构（`PICO_PLATFORM=rp2350-arm-s`）**。
* **理由对比**：
  * **Arm Cortex-M33**：芯片具备 **Arm TrustZone-M** 硬件隔离能力。**但要注意**：pico-sdk 2.3.1 只提供 `rp2350-arm-s` 平台，没有 `rp2350-arm-ns`；要在 RP2350 上真正跑 Non-Secure world，需要自定义启动代码、veneer 与链接布局，不能只靠 CMake 切换。RS-Key 也没有使用 NS world，而是全部运行在 Secure 态，靠 secure boot + OTP + 分区表防护。把“TrustZone 隔离私钥”当作 v1 的既有能力是不准确的，应先做 PoC。
  * **Hazard3 RISC-V**：虽然开源自由，但**不支持 Arm TrustZone**，无法构建芯片级硬隔离边界，且现有的密码学加速栈（如 mbedtls 汇编级对抗侧信道防护）对 Arm 的支持度成熟度远超 RISC-V。

#### (2) 内置硬件 SHA-256 加速器（`hardware_sha256` / `sha256_alt`）
* RP2350 内置专用的 32-bit SHA-256 引擎，支持以 64-byte 分块全速灌入，支持 DMA 直传。
* **MbedTLS 硬件替换**：
  在 `mbedtls_config.h` 中配置宏：
  ```c
  #define MBEDTLS_SHA256_ALT
  #define PICO_MBEDTLS_SHA256_ALT_USE_DMA 1
  ```
  Pico SDK 会自动调用硬件 SHA-256 引擎。实际加速比取决于调用模式（是否走 DMA、是否分块频繁）与基线实现；公开资料没有给出 FIDO2 端到端基准，应在目标板上用 `rsk-bench` 或自建基准测量。

#### (3) 硬件 TRNG（真随机数发生器）
* RP2350 搭载专用硬件 TRNG，其熵源是**内部 Ring Oscillator（ROSC）**的抖动采样，再经过采样/条件化产生 192 bit 熵输出；数据手册 §12.12 声明其符合 FIPS 140-2、BSI AIS-31 与 **NIST SP 800-90B**。注意：这是 IP 块的“合规声明”，不是 RP2350 的认证证书；bootrom 在某些路径上会绕过 TRNG 内部 conditioning。
* **不要写“彻底告别 ROSC”**：RP2350 的 TRNG 仍然使用 ROSC，区别是增加了专用 TRNG 块、采样与条件化，而不是像 RP2040 那样直接拿 ROSC 当随机源。
* 在 SDK 中引入 `pico_rand`：
  ```c
  #include "pico/rand.h"
  // 直接获得具备密码学强度的 32 位随机数
  uint32_t random_val = get_rand_32();
  // 128 位输出：注意是 out-param，返回 void，不是返回值
  rng_128_t auth_nonce;
  get_rand_128(&auth_nonce);
  ```
  这是 Passkey 生成不可预测私钥、FIDO2 Nonce 以及 AES-GCM IV 的根本保障。

---

### 3. 安全启动、固件签名与 OTP 熔丝

RP2350 的 BootROM 拥有内置的安全启动鉴权引擎。

```
+-------------------------------------------------------------+
|                     RP2350 芯片安全链                       |
|                                                             |
|  [ OTP 熔丝区 ]              [ 外部 2MB NOR Flash ]         |
|  - BOOTKEY0~3 (公钥哈希)      - 分区表 (Partition Table)     |
|  - SECURE_BOOT_ENABLE       - 固件 Slot A (带数字签名)       |
|  - CRIT1 关键安全标志       - 固件 Slot B (带数字签名)       |
|            |                                |               |
|            v                                v               |
|  +-------------------------------------------------------+  |
|  |             BootROM 硬件级鉴权 (secp256k1)            |  |
|  |  1. 校验公钥 Hash == OTP[BOOTKEY]                      |  |
|  |  2. 验证固件镜像数字签名合法性                          |  |
|  |  3. 检查版本防回滚 (Anti-Rollback)                     |  |
|  +-------------------------------------------------------+  |
|                            | (验签通过)                     |
|                            v                                |
|             [ Cortex-M33 Secure World 启动 ]                |
+-------------------------------------------------------------+
```

#### (1) 签名算法机制（注意：BootROM 为 `secp256k1`）
* **核心事实**：RP2350 BootROM 安全启动强制使用 **ECDSA secp256k1 + SHA-256**（非 P-256）作为固件签名算法。
* 虽然 FIDO2 协议层主要使用 NIST P-256 (`secp256r1`)，但**固件镜像自身**必须由开发者持有的 `secp256k1` 私钥进行封包与签名。

#### (2) 编译、封包与签名标准流水线
SDK 2.x 使用新一代 `picotool` 替代原有的 `elf2uf2`。

```bash
# 1. 生成开发者的 ECDSA secp256k1 密钥对
openssl ecparam -name secp256k1 -genkey -noout -out ohmykei_private.pem
openssl ec -in ohmykei_private.pem -pubout -out ohmykei_public.pem

# 2. 编译工程生成 ohmykei.elf

# 3. 使用 picotool seal 进行哈希、签名、元数据封包并导出 OTP 配置
#    注意：seal 要求输出与输入同类型；ELF 进必须 ELF 出，之后再转 UF2。
#    参数顺序：<infile> <outfile> <key.pem> <otp.json>；--sign 是 flag，不吃路径。
picotool seal --sign --hash \
    --major 1 --minor 0 --rollback 1 \
    ohmykei.elf ohmykei_signed.elf \
    ohmykei_private.pem otp_config.json

# 4. 再把 signed ELF 转成 UF2
picotool uf2 convert ohmykei_signed.elf -t elf ohmykei_signed.uf2
picotool info -a ohmykei_signed.elf   # 应显示 signature: verified
```

> 如果直接把 `.uf2` 写成 `seal` 的输出，picotool 2.3.1 会报 `ERROR: Can only sign to same file type`（`main.cpp:6137`）。这是最容易踩、也最容易误判为“签名成功”的一个错误。

#### (3) 2MB Flash 分区表（Partition Table）规划
针对 RP2350-Zero-CM 的 2MB Flash，创建 `partitions.json`。

**注意两个硬约束**：
1. picotool 的权限字段只接受 `r`/`w` 的组合（`"rw"`、`"r"`、`"w"`、`""`），**`"ro"`、`"rx"`、`"-"` 都是非法的**；
2. picotool 在 Flash 开头保留 **8 KB** 给两个 partition-table boot slot，2 MB 实际可用 **2040 KB**。896+896+252=2044 KB 超出可用空间，放不下。

```json
{
    "version": [1, 0],
    "unpartitioned": {
        "families": ["absolute"],
        "permissions": { "secure": "rw", "nonsecure": "", "bootloader": "rw" }
    },
    "partitions": [
        {
            "name": "Slot_A",
            "id": 0,
            "size": "896K",
            "families": ["rp2350-arm-s"],
            "permissions": { "secure": "rw", "nonsecure": "rw", "bootloader": "rw" }
        },
        {
            "name": "Slot_B",
            "id": 1,
            "size": "896K",
            "families": ["rp2350-arm-s"],
            "permissions": { "secure": "rw", "nonsecure": "rw", "bootloader": "rw" },
            "link": ["a", 0]
        },
        {
            "name": "Data_Credentials",
            "id": 2,
            "size": "248K",
            "families": ["data"],
            "permissions": { "secure": "rw", "nonsecure": "", "bootloader": "" }
        }
    ]
}
```
* 896 + 896 + 248 = **2040 KB**，正好用满；`248K` 是 4 KB 的整数倍（62 个 sector）。
* 数据分区的 `bootloader` 必须是 `""`（拒绝 BOOTSEL 读写），否则分区表围栏失效。
* 如果不需要 A/B 双槽，可以删掉 Slot_B 和 `link`，把空间都给 Data。
* 编译并**嵌入固件**（单独 load 一个分区表不会让固件受保护）：
  ```bash
  # 第三个位置参数是要嵌入分区表的固件 ELF；输出仍是 ELF
  picotool partition create partitions.json firmware-with-pt.elf firmware.elf -t elf
  # 或者生成独立 UF2（仅用于检查/合并，不要对纯分区表加 -x）
  picotool partition create partitions.json partition_table.uf2
  ```
  正确顺序是：**先嵌入分区表，再 `picotool seal` 签名**，否则签名不覆盖围栏。

#### (4) OTP 熔丝烧写与安全锁定
* 烧写公钥 Hash 与安全标志：
  ```bash
  # ⚠️ seal 生成的 otp_config.json 已经包含 bootkey0 + crit1.secure_boot_enable=1
  #    以及 boot_flags1.key_valid=1；load 它等于“一步开启安全启动”。
  #    研发阶段务必先 --dry-run/备份，确认签名镜像能启动后再烧！
  picotool otp load otp_config.json            # 先确认 JSON 内容与签名镜像都已验证

  # 如果只想单独置位（等价操作；selector 有效：OTP_DATA_ 前缀可省略）：
  picotool otp set OTP_DATA_CRIT1.SECURE_BOOT_ENABLE 1
  ```
  > 更稳妥的是采用 RS-Key 的分阶段流程（`rsk otp burn` → `rsk secure-boot load-key` → `harden` → `enable` → `lock`），每步都有 dry-run 与状态检查。

---

### 4. macOS 下开发环境最佳搭建指南

在 macOS（Apple Silicon / Intel）上，推荐以下两套搭建路径：

#### 方案 A：VS Code + 官方 Pico 扩展（推荐日常开发）
1. 打开 VS Code，在扩展市场安装 **`Raspberry Pi Pico`**（ID: `raspberry-pi.raspberry-pi-pico`）；
2. 插件会自动在后台下载并安装：
   * Pico SDK 2.x
   * 最新 Arm GNU Embedded Toolchain
   * Ninja、CMake
   * picotool 2.x
3. 状态栏提供直观的切换按钮：一键切换 Platform 为 `rp2350-arm-s`，一键 Compile / Run。

#### 方案 B：Homebrew 原生终端工具链（推荐 CI/CD 与高阶工程）
```bash
# 1. 安装构建工具链与 picotool 2.x
brew install cmake ninja picotool

# 2. 安装官方 Arm 工具链（推荐 14.2/15.3；GCC 13+ 不是硬性要求）
brew install --cask gcc-arm-embedded

# 3. 验证编译器版本
arm-none-eabi-gcc --version

# 4. 获取 Pico SDK 2.3.1（构建默认搜索 ~/.pico-sdk/sdk/2.3.1）
git clone --branch 2.3.1 --depth 1 --recurse-submodules \
    https://github.com/raspberrypi/pico-sdk.git ~/.pico-sdk/sdk/2.3.1
# 如果 SDK 放在别处：export PICO_SDK_PATH=/path/to/pico-sdk

# 5. 构建 OhMyKei 项目
cd /Users/zhecai/OhMyKei
cmake --preset fw-release
cmake --build --preset fw-release
cmake --build --preset fw-release --target flash
```

---

## 三、 落地建议速查清单

| 关注项 | 建议决策与配置 |
| :--- | :--- |
| **Flash 边界** | 使用官方 `waveshare_rp2350_zero.h`，在 target 上调用 `pico_override_flash_size(ohmykei 2097152)`；`main.c` 静态断言 `PICO_FLASH_SIZE_BYTES == 2097152` 兜底。 |
| **物理按键交互** | 采用在 RAM 中执行的 `read_user_presence_bootsel()` 采样逻辑，利用外壳上的 BOOT 按键作为物理触摸确认。 |
| **状态灯效** | 使用 GPIO 16 驱动 WS2812B，透过 3D 打印外壳透光层指示 FIDO2 等待触摸、认证成功等状态。 |
| **加密选型** | 平台选 `rp2350-arm-s`（Secure 态）。pico-sdk 2.3.1 没有现成的 Non-Secure 平台，**不要把“TrustZone 隔离私钥”当作 v1 既有能力**；先靠 secure boot + OTP + 分区表。开启 `MBEDTLS_SHA256_ALT` 使用硬件 SHA-256；随机数由 `pico_rand` 硬件 TRNG 支撑。 |
| **固件发布** | 先把 2 MB 分区表嵌入 ELF，再用 `secp256k1` 签名并转 UF2；量产阶段烧写 OTP `BOOTKEY`（必要时同时烧 MKEK）建立硬件信任根。 |
