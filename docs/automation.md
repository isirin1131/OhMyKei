# 无真机自动化测试

当前路径：Colima ARM64 → Linux UHID → 原有 CTAPHID/CTAP/存储/密码学核心。
`python-fido2` 通过系统 hidraw 访问设备，独立验证签名与协议行为。

## 一键回归

前提：macOS 已安装 Docker CLI 和 Colima，默认 Colima 实例正在运行，项目目录已挂载。

```sh
python3 host/virtual/run.py test
```

首次运行下载固定基础镜像并构建 `ohmykei-virtual:1`。若缺少 UHID，脚本从 Ubuntu
软件源下载与当前虚拟机内核匹配的 `linux-modules-extra` 包，只提取和加载
`uhid.ko`；不安装其他驱动，不升级内核。重启 Colima 后同一命令会重新加载模块。
构建目录独立为 `build/virtual-hid/linux`，不会混用 macOS 的 `build/host`。

专用容器名为 `ohmykei-virtual`。脚本显式使用默认 Colima socket，不修改 Docker
context。容器使用 UHID 与 hidraw 的设备权限，不需要 `--privileged`。
编译与运行均启用 ASan 和非恢复 UBSan。十一项核心回归（含 Wycheproof/NIST 向量）通过后，运行十四项 HID 回归：

- GetInfo、INIT 和 1500 字节 PING 分片。
- ES256/Ed25519 自认证和断言独立验签、计数器递增。
- hmac-secret-mc 与 GetAssertion 扩展输出一致，覆盖协议 1/2 交叉使用和单盐/双盐。
- 驻留凭据和计数器跨重新上电保留。
- PIN 协议 1/2、设置/修改 PIN、UV、重试次数持久化、协议切换及非法协商输入后的恢复。
- 重新上电使旧 PIN token 失效。
- CredentialManagement 枚举和删除。
- MakeCredential 与 Selection 等待 UP 时的 Keepalive/CANCEL，以及取消后的正常请求。
- 请求字段和列表项类型、合法项前后的非法项、算法偏好及未知类型兼容。
- 不支持的 enterpriseAttestation 参数明确拒绝。
- 设置 PIN 后 credProtect 1/2/3 的发现/allowList、UP/UV、签名和用户名称限制。
- 官方用户在场 HTTP 入口；空闲触摸拒绝。
- Reset 超过十秒拒绝、重新上电后恢复窗口，Reset 清空 PIN/凭据。

每项测试使用独立的合成 Flash 文件，每轮报告写入
`build/virtual-hid/runs/run-*/result.json`。不会读取真机或真实凭据。
首次验证：九项核心测试 14.91 秒；十项 HID 回归 18.28 秒。下载/构建耗时另计。

2026-11-06 密码学回归扩展：主机 Debug + ASan/UBSan **14/14**，Linux 核心
**11/11**（23.69 秒）、HID **14/14**（26.061 秒）；HID 报告为
`build/virtual-hid/runs/run-tbry_pwo/result.json`。公开向量涵盖 958 项 Wycheproof
和 1,889 项 NIST，详情见 [密码学回归](crypto-testing.md)。HKDF 超限输出由静默
截断改为返回失败且不写输出；固件布局检查通过。此轮未重跑官方全量套件。

## 持续运行虚拟设备

```sh
python3 host/virtual/run.py serve
```

使用独立持久化文件 `build/virtual-hid/device.flash`，默认在等待 UP 后 250 ms 自动触摸。
HTTP 只发布到 Mac 的 `127.0.0.1:3000`。Ctrl-C 或下列命令停止专用容器及其虚拟设备：

```sh
python3 host/virtual/run.py stop
```

| HTTP | 行为 |
|---|---|
| `GET /health` | 本次启动编号和虚拟设备路径 |
| `POST /control/mode`，`{"auto_touch_ms":null}` | 手动触摸模式 |
| `POST /control/mode`，`{"auto_touch_ms":250}` | 延迟自动触摸（10–10000 ms） |
| `POST /conformance/userpresence` | 确认当前等待 UP 的请求；未等待时返回 503 |
| `POST /conformance/powercycle` | 保留 Flash、终止/重新启动核心并重新枚举，完成后返回 |
| `POST /conformance/results` | 仅保存官方结果总数，不保存报文或凭据内容 |

`/control/touch` 和 `/control/powercycle` 是相同操作的测试别名。
HTTP 服务是测试控制面。模拟器可见于 Colima/Linux；Mac 上的原生 HID 客户端不会
自动看到虚拟机内部的设备。

## 官方工具

本地工具版本 1.9.3.1，Electron 为 41.7.0。`prepare_official.py` 按字节复制
运行源码与测试模块并记录哈希；Linux 原生依赖单独重建，官方测试、断言、HID
实现和 Mocha 均不修改。npm 使用从已验证镜像提取的锁文件和 `npm ci`。
临时使用期间复用已构建镜像；apt 软件包未建立快照，重建后以报告中的镜像 ID 区分环境。

```sh
# 默认执行 CTAP 2.3 认证器完整清单
python3 host/virtual/run.py official

# 约数秒的 GetInfo / PIN 协商冒烟
python3 host/virtual/run.py official --suite smoke

# 只跑元数据；--group 可重复指定，名称来自官方 authr-testlist.json
python3 host/virtual/run.py official --group Metadata

# 用官方 Mocha 的标题正则筛选某一组中的用例
python3 host/virtual/run.py official --group MakeCredentialRequest --grep 'F-9'
```

默认全量截止时间为 1800 秒，冒烟为 180 秒；可用 `--timeout 秒数` 修改。
每轮在 Xvfb 中启动干净的 Electron 会话，使用空的合成 Flash、独立配置目录和
官方 HTTP 自动化回调提供 UP。结束或超时后停止该会话的设备、Electron 和 Xvfb。
不置前 macOS 窗口、不注入键鼠，也不覆盖官方重试策略。
接口依据：[FIDO Automation.md](https://github.com/fido-alliance/conformance-test-tools-resources/blob/main/docs/FIDO2/Automation.md)。

统一报告为 `build/virtual-hid/official/session-*/result.json`，运行中持续保存：

- 本轮选择的文件、完整用例标识、最终状态、未完成项和重试事件。
- 官方跳过状态；Mocha 不提供跳过原因，报告明确标注未提供，不自动猜测为能力不适用。
- 脱敏错误类别、CTAP 状态码和源码栈位置；不保存原始报文、断言载荷或 PIN/token。
- 源码提交、工作区是否有已跟踪修改、镜像 ID，以及二进制、元数据、驱动、依赖锁和
  官方源码清单的 SHA-256。`environment.json` 单独保留相同环境信息。

退出码：`0` 表示所选测试完整结束、无失败、至少一项通过且选中的必跑基线通过；
`1` 表示完整执行后有测试失败；`2` 表示环境异常、超时、漏跑或无法判断（例如全跳过）；
`130` 表示中断。必跑基线为 GetInfo P-1/P-2/P-3 与 PIN 1/2 协商 P-1；分组或正则
筛选时只要求其中被选中的用例。用例总数动态来自官方清单，不硬编码 326。

固定测试元数据位于 `host/virtual/metadata.json`；空库容量期望独立设为 64，
不使用本轮响应生成期望。元数据已修正 CTAP 版本映射、FIDO2 不适用的顶层
`supportedExtensions` 和 MDS3 `legalHeader`。

2026-11-04 首轮全清单结果：**183 通过、118 官方跳过、25 失败**，734.027 秒。
其中 4 个失败属于上述元数据配置，其余 21 个协议用例当时尚待定位；不能等同于
25 个独立固件缺陷。历史报告为 `session-zazn96l0/full-result.json`。
完善后的全量验收：**187 通过、118 官方跳过、21 失败**，731.067 秒，退出码 `1`；
326 项全部有最终状态，没有漏跑、重复或必跑项跳过。63 次官方重试全部来自最终失败
用例。报告为 `build/virtual-hid/official/session-llwe__pk/result.json`。
元数据分组为 25 通过、12 跳过、0 失败，确认旧的 4 项配置错误已消除。

2026-11-05 协议核心迭代：补齐请求字段/完整列表校验、明确拒绝不支持的企业证明、
修正 Selection 取消状态，按 credProtect 策略替代无 allowList 时的统一 PIN 拦截。
官方定向为 **76 通过、12 跳过、0 失败、0 重试**（203.657 秒），旧 21 个失败逐项
转为通过；报告为 `session-pmwj0lzb/result.json`。
最终全量为 **208 通过、118 跳过、0 失败**（582.138 秒，退出码 0），
326 项无漏跑/重复且必跑项全部通过；报告为 `session-mfhksb5e/result.json`。

**已知官方断言冲突**：`Authr-ClientPin2-Policy / F-2` 随机生成 64–128 字节输入，
统一期望 `PIN_POLICY_VIOLATION(0x37)`。本轮三次收到 `INVALID_PARAMETER(0x02)`，
第四次通过。[CTAP 2.3 §6.5.5.5](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)
明确规定 paddedNewPin 非 64 字节应返回 `INVALID_PARAMETER`；固件保留该行为。
核心回归固定覆盖 64/80/96/112/128 字节、PIN 协议 1/2，区分 PIN 策略错误与
长度错误；新增后 `test_ctap` 再次通过（2.69 秒）。未修改官方断言或隐藏重试；后续官方随机轮次可能在此项失败，
本次零失败不意味着该套件已能稳定无重试通过。

另已验证：7/7 判定回归、冒烟 5/2/0 返回 `0`、NFC 全 8 项跳过返回 `2`、一秒
截止留下不完整报告并返回 `2`；supervisor SIGTERM 与宿主 Ctrl-C 均返回 `130`。
宿主中断后可正常重启完整会话。本地镜像关闭构建证明生成，重复缓存构建摘要稳定，
能复用容器。2026-11-05 固件迭代后自有回归为 9/9 核心（14.39 秒）和
13/13 HID（22.899 秒）通过；新增测试在修复前已复现对应缺陷。


2026-11-05 后续去耦合：ClientPIN 和 hmac-secret 共用 `omk_pin_protocol`，
签名/扩展输出去掉无用认证器参数，PIN 哈希缓冲区改为实际 16 字节。
新增独立客户端的协议 1/2 交叉、单双盐、MC/GA 扩展输出与签名回归，原实现和
收敛后均通过。收敛后 **9/9 核心（14.45 秒）、14/14 HID（26.192 秒）**，
报告为 `build/virtual-hid/runs/run-tsuw7n2f/result.json`；固件布局检查通过。
本轮官方全量 **208 通过、118 跳过、0 失败**（579.020 秒，退出码 0），326 项
最终状态与前轮一致，无漏跑/重复/必跑项跳过。ClientPin2-Policy F-2 收到一次
`0x02` 后重试通过；仍为上述已知断言冲突，未修改官方套件或固件错误码。
报告：`build/virtual-hid/official/session-nu4hfwxm/result.json`。

2026-11-05 ClientPIN 生命周期收敛：协议号和派生 AES/HMAC 密钥改为请求局部数据，
统一在子命令返回后擦除；长期设备状态、Reset 和密钥轮换不再保存或清理这些字段。
增强现有 PIN 回归，覆盖协议 1/2、错误 PIN 与重启后重试次数、非法协商点后的
正常 token 签发和 UV 验签。增强回归在原实现和修改后均通过；修改后
**9/9 核心（14.33 秒）、14/14 HID（26.905 秒）**，报告
`build/virtual-hid/runs/run-xbdh0tjp/result.json`。固件布局检查及子代理只读审查通过。
官方定向 `--group ClientPin1 --group ClientPin2 --group Reset --group Extensions
--group CredManAPI` 为 **94 通过、53 跳过、0 失败、0 重试**（357.876 秒）；147 项
完整结束且最终状态与前轮全量对应项一致。报告 `session-qwv59l_5/result.json`；
本轮未重跑官方全量。

2026-11-05 ClientPIN 响应编码去冗余：key agreement 响应复用现有
`omk_cbor_put_raw`，替代手写逐字节复制和重复容量检查，保留编码器溢出处理。
**9/9 核心（14.57 秒）、14/14 HID（26.841 秒）**通过，报告为
`build/virtual-hid/runs/run-fv2amjoz/result.json`；固件布局检查和子代理只读审查通过。
官方 ClientPin1/ClientPin2 首轮 **31 通过、18 跳过、1 失败**（97.365 秒），
唯一失败为上述已知 `ClientPin2-Policy / F-2` 断言冲突，3 次重试后仍失败；
报告 `session-nqdvrtge/result.json`。第二轮 **32 通过、18 跳过、0 失败**
（95.797 秒），F-2 在 1 次重试后通过，50 项无漏跑/重复/必跑项未通过；
报告 `session-nhrlfw32/result.json`。第二轮传入的 `--grep '^(?!.*F-2)'`
未排除该用例，以上结果按实际执行的全部 50 项记录。这不代表已知随机断言冲突
消失；未修改官方断言或固件错误码，本轮未重跑官方全量。

2026-11-05 ClientPIN 哈希校验去冗余：changePIN、getPinToken 和
getPinUvAuthTokenUsingPinWithPermissions 共用私有 `pin_verify_encrypted_hash`，
集中处理 16 字节 PIN 哈希的解密、校验和明文擦除。参数检查、MAC 校验、
重试计数及错误码顺序保持原样；changePIN 的旧 PIN 哈希在校验后立即擦除。
**9/9 核心（14.61 秒）、14/14 HID（26.787 秒）**通过，报告为
`build/virtual-hid/runs/run-9qiv9rbx/result.json`；固件布局检查和子代理只读审查通过。
官方 ClientPin1/ClientPin2 **32 通过、18 跳过、0 失败**（94.246 秒），50 项
无漏跑/重复/必跑项未通过。已知 `ClientPin2-Policy / F-2` 断言冲突出现一次，
由官方套件重试后通过；报告 `session-4w7yuo_3/result.json`。本轮未重跑官方全量。

2026-11-07 共享 CBOR 核心去冗余：map 键在解析时与已完成的键值对比较，
去掉每次比较都从链表头定位的辅助函数和不可达的缺节点分支；固定 arena 中
的节点地址保持稳定。去重遍历从三次方级降为平方级，不增加堆分配或硬件依赖。
同时修复重复 `null` 键漏检；文本与字节串编码复用 `omk_cbor_put_raw` 的容量
检查和复制，溢出结果仍须丢弃。新增回归覆盖标量键类型、嵌套作用域、节点上限、
截断 map、恰好容量及越界 canary；新增测试在原实现上复现重复键漏检。
**macOS ASan/UBSan 14/14（33.05 秒）、Linux 核心 11/11（21.61 秒）、
HID 14/14（26.443 秒）**通过；报告为
`build/virtual-hid/runs/run-fja_bih6/result.json`。ARM 固件构建、布局检查及
子代理只读审查通过。此次改动直接编入同一份固件核心，无需设备端重写。
本轮官方完整套件 **208 通过、118 跳过、0 失败**（578.355 秒，退出码 0），
326 项均有最终状态，无漏跑、重复、额外用例或必跑项未通过。已知
`ClientPin2-Policy / F-2` 断言冲突出现一次（实际 `0x02`、期望 `0x37`），
由官方重试后通过；报告为 `build/virtual-hid/official/session-j4j24xd6/result.json`。
CBOR fuzz 未运行：已有 fuzz 目录缺少构建文件，系统 Clang 链接探测确认
缺少 `libclang_rt.fuzzer_osx.a`，未安装新工具链。

2026-11-07 注册／登录流程收敛：MakeCredential 的格式偏好检查、正常注册路径中的
`hmac-secret-mc` 解析提前到 UP 和凭据生成之前；扩展值的 map 类型检查由共享
解析函数负责，新增早退路径统一擦除临时数据。MC/GA 共用 PIN 协议解析与空授权
参数探测处理，保留探测优先规则、各自的缺 PIN 策略以及无凭据时的 PUAT 恢复。
GetAssertion 复用现有 authenticatorData 构造函数，统一字段编码和容量检查。
新增回归覆盖三类错误注册输入在有／无自动触摸时不等待、不调用 RNG、不推进
计数器，以及 PIN 协议 1/2、有／无 PIN 的 MC/GA 探测。原实现触发 14 条新断言
失败，修复后通过；现有验签、扩展输出、取消和无凭据授权状态回归也通过。
**macOS ASan/UBSan 14/14（36.09 秒）、Linux 核心 11/11（21.92 秒）、
HID 14/14（26.421 秒）**通过，HID 报告为
`build/virtual-hid/runs/run-t7xa62fv/result.json`。ARM 固件构建、布局检查及
子代理只读审查通过。
官方完整套件 **208 通过、118 跳过、0 失败**（584.215 秒，退出码 0），
326 项无漏跑、重复、额外用例或必跑项未通过。上述已知 `ClientPin2-Policy / F-2`
断言冲突出现 3 次（实际 `0x02`、期望 `0x37`），第四次执行通过；未修改官方
测试、元数据或重试策略。报告为
`build/virtual-hid/official/session-05ud9q15/result.json`。

依赖镜像变化时，脚本停止并重命名旧专用容器后创建新容器，不删除旧容器。
`python3 host/virtual/run.py stop` 停止当前两个专用容器。报告保留，临时合成 Flash
和浏览器配置在任务完成后移入回收站；不读取其中的凭据数据。

## 覆盖边界

此路径执行真实协议与密码学代码，并使用实际 Linux HID 栈。Flash 模型保留
256 字节页对齐、4 KiB 扇区和 NOR 1→0 约束，写入完成前同步文件。
重新上电保留 Flash、清空易失状态；使用单调实时时钟，保留超时语义。
它不模拟 RP2350 指令、TinyUSB/USB 控制器、硬件随机源或真实 Flash 时序。
当前 dev 阶段不引入 OTP 熔丝、boot 锁定或刷写操作。
