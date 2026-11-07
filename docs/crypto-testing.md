# 自有密码学回归

继续维护 `src/crypto` 的纯 C17 实现。公开向量在主机上直接调用与固件相同的
`omk_core`，测试桥接器不重新实现密码学算法。自有代码和适配器继续 MIT；
Wycheproof 数据保留 Apache-2.0 许可，不编入固件。

## 运行

需要 CMake、C 编译器和 Python 3；不需要额外 Python 包、网络或真机。

```sh
cmake --preset host
cmake --build --preset host
ctest --preset host

# 只跑公开密码学向量
ctest --test-dir build/host -R '^test_crypto_(wycheproof|nist)$' --output-on-failure

# Linux 核心与 HID 端到端回归
python3 host/virtual/run.py test
```

默认 host preset 为 Debug + ASan 和非恢复 UBSan，共 14 项 CTest。
两个 Python 驱动复用 `host/tests/crypto_vector_bridge.c`，通过标准输入/输出批量
调用生产 API。解析/容量错误和子进程异常必须使测试失败；生产函数拒绝输入才
能被记作正确拒绝。失败日志只报告文件、用例编号和类别，不打印测试载荷。

## 固定数据与判定

`host/vectors/wycheproof/manifest.json` 固定上游提交和原始文件 SHA-256；
`host/vectors/nist/manifest.json` 记录官方 ZIP 地址、归档哈希、所取成员与原始
文件哈希。每轮运行验证文件哈希。所有数据均为公开标准向量，不是真实凭据。

| 来源/原语 | 执行项 | 不适用项 | 判定 |
|---|---:|---:|---|
| Wycheproof HMAC-SHA256 | 87 | 87 | 完整 32 字节 MAC；修改后的 tag 用 `omk_ct_equal` 检查 |
| Wycheproof HKDF-SHA256 | 86 | 0 | 包括 8160 字节最大输出、8161 字节拒绝且不写输出 |
| Wycheproof P-256 ECDSA | 241 | 21 | P1363 原始签名；非 64 字节签名不传入固定宽度 API |
| Wycheproof Ed25519 | 198 | 12 | 非 64 字节签名不适用；包含 29 项上游 acceptable 策略用例 |
| Wycheproof P-256 ECDH | 346 | 9 | 65 字节点；其他点编码不适用；整数标量只做无损补零/去前导零 |
| NIST AES-256 ECB/CBC | 1660 | — | KAT 与多块 MMT，分别校验加密/解密，附加原位与 IV 不变检查 |
| NIST SHA-256 | 229 | — | 65 短消息、64 长消息、100 Monte Carlo 检查点（100,000 次哈希） |

共执行 **958 项 Wycheproof + 1,889 项 NIST**。129 项不适用是接口范围限制，
不计入执行成功数；无 DER/PEM 解析、压缩点、Ed25519ph/ctx 或 CBC padding 覆盖。
SHA 消息向量同时检查单次输入和 1/63/64/65 字节分块输入。
现有 RFC 4231/5869/6979/8032 单元测试继续覆盖签名生成、确定性输出和随机源失败。

Ed25519 规则：`valid` 必须接受，`invalid` 必须拒绝。上游 `acceptable` 的小阶
公钥按现有接口政策要求拒绝；混合阶公钥允许接受或拒绝，并分别报告数量。
现有实现采用 RFC 8032 允许的非 cofactor 验证等式；不因上游兼容性差异擅自
改变验签规则。当前 acceptable 结果为 21 接受、8 拒绝，不代表 29 项都要求接受。

更新数据时，按固定提交/官方归档取原文件，保留 LICENSE，更新清单与计数。
检查新增 flags、算法参数和接口适用性，再运行完整回归；不能以更新预期或增加
跳过项代替分析失败。NIST 文件保持原始字节，含原始行尾。

来源：[Wycheproof](https://github.com/C2SP/wycheproof)、
[NIST AES](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers)、
[NIST SHA](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing)、
[SHAVS](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/SHAVS.pdf)。

## 本轮修复与验证（2026-11-06）

HKDF 原来把超限长度静默截断到 8160 字节，不能向调用者报告输出不完整。
现在返回 `bool`：超限返回 false 且不访问输入/写输出；零长度成功且不写输出。
现有固件调用均使用固定 32 字节输出，保持原行为，无需新增不可达的错误分支。
HMAC final 已擦除内部状态和外层 pad，HKDF 移除了对这些状态的重复擦除，继续
擦除自身的 PRK 和中间块。

正式 host Debug 配置 14/14，Linux 核心 11/11，虚拟 HID 14/14，RP2350 Release
固件构建与 `layout-check` 通过。本轮未重跑官方 FIDO 全量套件。
另行尝试的 macOS RelWithDebInfo + ASan 构建中，公开密码学向量通过，
`test_store` 在测试入口报告栈溢出；正式 Debug 配置没有该失败。本轮未修改存储测试。

这些结果证明所列输入与接口回归通过，不是 CAVP/FIDO 认证或密码学安全证明。
尚未完成 RP2350 上的恒定时间、功耗/电磁侧信道或随机源质量验证，也没有据此
声称所有算术路径均被覆盖。
