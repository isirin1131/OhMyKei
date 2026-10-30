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
- **测试与验证**：以 **FIDO Alliance 官方测试套件 v1.9.3.1**（包含 CTAP 2.3 测试模块）为功能一致性与合规基准；社区针对 FIDO2 / CTAP 标准的开源测试集后续按需评估。

## 当前状态

- 已有 CMake 固件 / host / fuzz 预设、2 MB Flash 配置和刷写目标。
- 固件目前是板级点亮阶段：BOOTSEL 采样、WS2812 LED 和 USB CDC 调试输出演示。
- host / fuzz 只有 smoke test，尚无协议覆盖。
- FIDO2 / CTAP 2.3 协议栈、加密子系统和凭据存储未实现。测试套件已在本地就绪。构建与刷写说明见 [README](../README.md)。

## 开发顺序

1. **FIDO2 基本流程**：
   - 接入硬件真随机源（TRNG/ROSC）、P-256 与 SHA-256 密码学、Flash 凭据存储骨架。
   - 实现 USB CTAPHID 报文分片与通道管理、标准 CBOR 编码/解析。
   - 实现 `authenticatorGetInfo`、`authenticatorMakeCredential`、`authenticatorGetAssertion` 最小功能集。
   - 用浏览器或 `libfido2` 验证注册、登录、触摸按键确认（UP）、保活（Keepalive）与超时取消。

2. **FIDO2 完备功能与扩展**：
   - 实现 PIN/UV Auth Protocol 2（32 字节 Token 机制、AES-256-CBC、HMAC-SHA-256）。
   - 实现驻留凭据（Passkeys / Discoverable Credentials）及凭据管理（`credMgmt`）。
   - 补齐 Ed25519 签名算法（支持 `ssh-ed25519-sk`）。
   - 实现核心扩展：`hmac-secret`（支持 `age` 文件加密与 WebAuthn PRF）、`credProtect`、`credBlob` 及 `minPinLength`。
   - 用 OpenSSH-SK、Git SSH 签名、`age-plugin-fido2-hmac` 及支持 PRF 的客户端验证实际用途。

3. **一致性测试与固件加固**：
   - 跑通 **FIDO Alliance 官方测试套件 v1.9.3.1**（CTAP 2.3 模块）对应的全量测试项。
   - 完善 Flash 掉电保护、擦写磨损均衡、PIN 错误重试锁定（Power cycle 递减）与敏感内存擦除。

管理、备份恢复和重置工具随实际使用需求再安排。

## 实现要求

- USB 输入解析与协议状态机可在 host 测试；随实现补边界、越权、超时、取消测试及 libFuzzer + ASan/UBSan 覆盖。
- 耗时操作和等待按键期间保持 USB HID 响应，严格执行 CTAPHID Keepalive 保活。
- 按协议执行 UP / PIN 检查，敏感上下文严格使用安全擦除，验证 PIN 重试限制和存储掉电一致性。

密码学库选型、凭据存储布局、调度方式及安全启动方案，留到对应阶段实现时决定；记录已验证的结论，不预设接口、伪代码或未经验证的性能指标。

## 参考规范与工具

- [CTAP 2.3 Proposed Standard (2026-02-26)](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)
- [CTAP 2.1 Proposed Standard](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html)
- [RP2350 Datasheet](https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf)
- **官方一致性测试套件**：FIDO Alliance Certification Conformance Testing Tools `v1.9.3.1`（CTAP 2.3 模块）
