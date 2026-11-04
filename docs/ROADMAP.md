# Roadmap

只记录目标、现状和开发顺序。具体设计随实现、规范验证和硬件实测确定。

## 目标与边界

- **定位**：纯 FIDO2 / CTAP 2.3 硬件安全密钥与通行密钥（Passkey）固件，向下兼容 CTAP 2.1 / 2.0。面向现代开发者工作流（WebAuthn、SSH-SK / Git 签名、基于 `hmac-secret` 的 `age` 文件加密与密码管理器 PRF）。
- **硬件**：Waveshare RP2350-Zero-CM（RP2350A、2 MB Flash、USB Type-C 公口）；纯 C17 / MIT 许可。
- **接口形态**：单 USB HID 设备接口（Usage Page `0xF1D0`），零驱动依赖。
- **算法范围**：P-256 (ES256)、Ed25519 (EdDSA)；内部密钥派生支持 SHA-256、HMAC-SHA-256、HKDF-SHA-256 及 AES-256。
- **明确不做**：
  - 不做 CCID / ISO 7816 / OpenPGP Card（文件加密由 `age` + `hmac-secret` 承载，Git/SSH 签名由 native FIDO2 承载）。
  - 不做 CTAP1 / U2F、OATH TOTP、PIV、RSA、`largeBlobs`、键盘 HID、Yubico OTP、NFC、BLE、生物识别或厂商云依赖。
- **安全与合规**：
  - 按公开规范独立实现，不复制或逐行翻译其他项目源码；外部依赖仅限宽松开源协议（MIT / BSD / ISC / CC0 / Apache-2.0）。
  - **硬件存储安全关注**：RP2350 在 BOOTSEL 模式下可通过 picotool 直接回读外部 Flash。当前主密钥与 PIN 哈希仍以明文存放，尚无语义上的 OTP 密钥封装、安全启动、BOOTSEL 回读防护或固件防回滚；只靠固件逻辑不能提供针对物理接触的保证。旧凭据记录通过 bank 选择与 log epoch 失效，历史 meta 快照被更高 seq 的完整快照取代，但都**不保证已被安全擦除**。当前 USB 身份仍使用未分配的开发 PID `2E8A:10A1`，发布前必须替换为已分配 VID/PID。
- **测试与验证**：以 **FIDO Alliance 官方测试套件 v1.9.3.1**（CTAP 2.3 模块，默认 / 非 featureful 配置）为功能一致性与合规基准；社区针对 FIDO2 / CTAP 标准的开源测试集后续按需评估。

## 当前状态

- 2026-11-04：Colima + UHID 自动化链路已打通；真实 `omk_core` 的九项 Linux
  sanitizer 测试和十项 `python-fido2` HID 端到端回归通过。包含独立验签、PIN、
  凭据管理、持久化、取消与 Reset 窗口；使用方法和官方工具接入状态见
  [自动化测试](automation.md)。此结果不等同于官方套件全量通过或硬件实测。
- 官方 v1.9.3.1 已在 Linux Electron 41.7.0 下连接虚拟设备，选定的 GetInfo、
  PIN 1/2 密钥协商最小集为 **5 通过 / 2 能力不适用跳过 / 0 失败**；首轮完整
  CTAP 2.3 清单为 **183 通过 / 118 官方跳过 / 25 失败**。修正元数据并完善工具后，
  工具验收为 **187 通过 / 118 官方跳过 / 21 失败**。2026-11-05 核心修复后，
  定向为 **76/12/0**（无重试），全量为 **208/118/0**，无漏跑；旧 21 项全部通过。
  全量有一个超长 PIN 用例三次重试后通过，其断言与规范的长度错误码要求冲突，
  详见 [自动化测试](automation.md)。当前自有回归为 9/9 核心、13/13 HID 通过。
  已提供全量／冒烟／定向入口、报告与依赖锁，7 个框架判定回归通过。
  官方源码、断言和 HID 实现均未修改。

- 2026-11-04：修复 ES256 DER 签名、凭据管理 descriptor map、MakeCredential
  `attestationFormatsPreference (0x0B)`；断言改用轻量标量检查，枚举首条/续页
  共用响应编码，入口校验后的 RP 哈希直接传入内部函数。对应报文及边界回归已通过。

- 协议核心已实现并可构建：CTAPHID（通道/分片/Keepalive/CANCEL/中止）、严格 CBOR、
  P-256/Ed25519、Flash 凭据存储、`GetInfo`/`MakeCredential`/`GetAssertion`/
  `GetNextAssertion`/`ClientPIN` 1+2/`Reset`/`Selection`/`CredentialManagement`，
  以及 `hmac-secret`/`hmac-secret-mc`/`credProtect`。
- 持久化使用 **v2 追加式 meta 日志**（8 个扇区 × 256 B 快照，CRC + 单调序号）和
  **双 bank 凭据日志**（每 bank 496 KiB：124 个 4 KiB 扇区、496 个 1 KiB 槽位）。
  bank 满时把 live 凭据复制到非活动 bank，校验后由一条 meta 记录原子切换 bank 和
  log epoch；Reset 也通过新 epoch 使旧记录失效。PIN 重试在比较前先持久化“递减计数
  + 候选哈希”，启动时解析未决尝试。
- 固件为单 USB HID 接口（0xF1D0），UP 使用板载 BOOT 按键；已移除 CDC 调试口。
- host 端当前注册 **12 个 CTest**（默认 ASan + 非恢复 UBSan）；2026-11-04
  CTAP/PIN 清理后九个可执行测试通过；三个构建探针在此前协议修复轮以无删除
  临时副本执行通过，本轮未重复执行。注册项包含：
  8 个单元/回归可执行文件、CTAPHID fuzz replay、UBSan 非恢复探针、固件版本定义
  探针、核心无 fuzzer hook 检查。CBOR/CTAPHID 另有 libFuzzer 目标；fuzz preset
  需要 libFuzzer runtime，缺少时配置会给出明确错误。本机 Apple clang 没有该
  runtime，**本 checkout 未运行 fuzz**；命令层 harness 已改为调用真实
  `omk_ctap_handle`，但只有实际 fuzz 运行才算覆盖。CI 已加入对应 runtime 安装，
  尚未取得远端执行结果。
- 固件 Release 构建于 2026-11-04 通过 `layout-check`：32 KiB 主栈、`__StackLimit`/`__HeapLimit`
  等于栈底、镜像结束地址低于上半 1 MiB 存储区。
- CTAP/PIN 五项技术债已清理：重复曲线校验、解密成功后的长度复查、无运行时用途的
  状态标记、重复 PUAT 查询接口，以及扩展 HMAC 派生结果的长期保存。
  输入边界与实际授权检查保留；验证见 [审计记录 5.5](audit-plan.md#55-2026-11-04-ctappin-过度防御清理)。
- 2026-11-03 审计修复已落地：pinUvAuthProtocol 缺省、credProtect 回显、删除后的
  凭据/RP 枚举、同次上电脏槽重试、compaction/Reset 协作取消、固定型号 AAGUID、
  存储错误分类和 CBOR 容量检查。仍有关键发布阻塞：RNG 健康/故障传播、未分配
  USB PID，以及尚无持久化格式迁移。
- 尚未在硬件上使用 FIDO Alliance 官方测试套件 v1.9.3.1（CTAP 2.3 默认配置）
  跑一致性测试，也没有物理掉电/欠压测试；second batch
  （authenticatorConfig/credBlob/largeBlobs/alwaysUv、`minPinLength` 策略）尚未实现，
  getInfo 未声明。
- v1、未知版本和 foreign magic 的 meta 镜像会使 init 失败且**不写不擦**；没有
  v1→v2 迁移。掉电若发生在 meta 扇区擦除中途，可能留下无法识别的部分记录，
  同样需要显式恢复而不是自动格式化。
- 主密钥与 PIN 哈希仍以明文存放于外部 Flash；OTP/安全启动加固、物理掉电压测与
  BOOTSEL/防回滚属于第 3 阶段。当前 dev 阶段不实施 OTP 熔丝或 boot 刷写锁定，
  不将这些明确未纳入范围的内容列为本轮缺陷。

## 开发顺序

1. **FIDO2 基本流程**（FIDO2 流程已实现；RNG 加固、硬件与浏览器/libfido2 实测未完成）：
   - 接入 P-256 与 SHA-256 密码学、Flash 凭据存储骨架；RNG 目前由 `pico_rand`
     提供，但熵源健康检查和故障传播仍未达标，列为发布阻塞。
   - 实现 USB CTAPHID 报文分片与通道管理、标准 CBOR 编码/解析。
   - 实现等待触摸确认（UP）期间不阻塞 USB 栈的并发模型（周期性 KEEPALIVE、当前 CID 取消、同 CID 中止重置及跨通道 busy 应答）。
   - 实现单调递增且掉电不回退的签名计数器持久化机制（64 值 lease）。
   - 实现 `authenticatorGetInfo`、`authenticatorMakeCredential`、`authenticatorGetAssertion` 最小功能集。
   - 用浏览器或 `libfido2` 验证注册、登录、触摸按键确认（UP）、保活（Keepalive）与超时取消。

2. **FIDO2 完备功能与扩展**（核心已实现；第二批未实现）：
   - 实现 PIN/UV Auth Protocol 2 和 1 以及兼容命令 `getPinToken`（复用 ECDH/AES-256-CBC/HMAC-SHA-256 原语，支持带权限 PUAT 机制）。
   - 实现驻留凭据（Passkeys / Discoverable Credentials）及凭据管理（`credMgmt`）。
   - 补齐 Ed25519 签名算法（支持 `ssh-ed25519-sk`）。
   - 实现核心扩展：`hmac-secret`（支持 `age` 文件加密与 WebAuthn PRF）、`hmac-secret-mc`、`credProtect`；`credBlob` 后补且尚未实现。
   - 第二批特性与扩展：`authenticatorConfig`（0x0D）及联动特性（`setMinPINLength` / `minPinLength` 扩展、`toggleAlwaysUv` / `alwaysUv` 特性），尚未实现。
   - 用 OpenSSH-SK、Git SSH 签名、`age-plugin-fido2-hmac` 及支持 PRF 的客户端验证实际用途（待硬件/客户端实测）。

3. **一致性测试与固件加固**（host 侧已有部分覆盖，硬件侧未完成）：
   - 跑通 **FIDO Alliance 官方测试套件 v1.9.3.1**（CTAP 2.3 模块，默认配置）对应的测试项。
   - host 侧已加入 NOR 风格掉电模型、逐操作 cut 测试、RNG 失败回归、compaction/Reset
     切换测试、PIN 候选哈希启动解析测试；但这不是物理掉电测试。
   - 待做：物理掉电/欠压压测、擦写磨损与坏块观察、OTP 密钥封装、安全启动、
     BOOTSEL 回读防护与固件防回滚、敏感内存擦除的形式化验证。

管理、备份恢复和重置工具随实际使用需求再安排。

## 实现要求

- USB 输入解析与协议状态机可在 host 测试；随实现补边界、越权、超时、取消测试及 libFuzzer + ASan/UBSan 覆盖。
- 耗时操作和等待按键期间保持 USB HID 响应，严格执行 CTAPHID Keepalive 保活。
- 按协议执行 UP / PIN 检查，敏感上下文严格使用安全擦除，验证 PIN 重试限制和存储掉电一致性。
- 当前 host 测试注册数量以构建配置为准（默认 12 个 CTest；关闭 sanitizer 时为 11 个；
  启用 fuzz 且 libFuzzer 可用时另加 4 个 fuzz 相关测试）。文档不把运行次数当成
  安全结论，也不替代物理硬件和一致性测试。

密码学库选型、凭据存储布局、调度方式及安全启动方案，留到对应阶段实现时决定；记录已验证的结论，不预设接口、伪代码或未经验证的性能指标。

## 参考规范与工具

- [CTAP 2.3 Proposed Standard (2026-02-26)](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)
- [CTAP 2.1 Proposed Standard](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html)
- [RP2350 Datasheet](https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf)
- **官方一致性测试套件**：FIDO Alliance Certification Conformance Testing Tools `v1.9.3.1`（CTAP 2.3 模块）
