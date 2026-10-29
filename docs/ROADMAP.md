# Roadmap

只记录目标、现状和开发顺序。具体设计随实现、规范验证和硬件实测确定。

## 目标与边界

- 硬件：RP2350-Zero-CM（RP2350A、2 MB Flash、USB Type-C 公口）；C17 / MIT。
- 先做 FIDO2 / CTAP 2.1，用于 WebAuthn、SSH / Git 签名及 `hmac-secret` 密钥派生；再做 CCID + OpenPGP Card 3.4。
- 算法范围：P-256、Ed25519、X25519。
- 不做 CTAP1/U2F、OATH、PIV、RSA、`largeBlobs`、键盘 HID、Yubico OTP、NFC、Web 控制台或厂商云依赖；使用合法 VID/PID。
- 按公开规范独立实现，不复制或逐行翻译其他项目源码；依赖限 MIT / BSD / ISC / CC0。
- RP2350 是通用 MCU，不承诺抵抗拆机或实验室级物理攻击。

## 当前状态

- 已有 CMake 固件 / host / fuzz 预设、2 MB Flash 配置和刷写目标。
- 固件目前是 BOOTSEL 采样、WS2812 LED 和 USB CDC 调试输出演示。
- host / fuzz 只有 smoke test，尚无协议覆盖。
- FIDO2、CCID / OpenPGP、凭据存储和管理 CLI 均未实现。构建与刷写说明见 [README](../README.md)。

## 开发顺序

1. **FIDO2 基本流程**：接入随机源、密码学和凭据存储，实现 CTAPHID、CBOR、`getInfo`、`makeCredential`、`getAssertion`。用浏览器或 `libfido2` 完成注册与登录，验证按键确认、超时和取消。
2. **FIDO2 实用功能**：补齐 PIN、驻留凭据及管理、Ed25519、`credProtect` 和 `hmac-secret`。用 OpenSSH 和支持 PRF 的客户端验证实际用途；兼容性以测试结果为准。
3. **OpenPGP**：实现 CCID / APDU 和 OpenPGP Card 3.4 的 ECC 子集，用 GnuPG 验证签名、解密、认证及 `pass` 使用。

管理、备份恢复和遗失撤销工具随实际使用需求再安排。

## 实现要求

- USB 输入解析与协议状态机可在 host 测试；随实现补边界、越权、超时、取消测试及 libFuzzer + ASan/UBSan 覆盖。
- 耗时操作和等待按键期间保持 USB 响应，验证保活与取消行为。
- 按协议执行 UP / PIN 检查，清除临时敏感数据，验证 PIN 重试限制和存储掉电一致性。

密码学库、凭据格式、Flash 布局、调度方式、备份方案及安全启动 / 锁板流程，留到对应功能实现时决定；记录已验证的结论，不预设接口、伪代码或性能数字。

## 参考规范

- [RP2350 Datasheet](https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf)
- [CTAP 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html)
- [OpenPGP Card 3.4](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf)
- [USB CCID 1.1](https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf)
