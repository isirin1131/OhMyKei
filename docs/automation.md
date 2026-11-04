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
编译与运行均启用 ASan 和非恢复 UBSan。九项核心测试通过后，运行十项 HID 回归：

- GetInfo、INIT 和 1500 字节 PING 分片。
- ES256/Ed25519 自认证和断言独立验签、计数器递增。
- 驻留凭据和计数器跨重新上电保留。
- PIN 协议 1/2、设置/修改 PIN、UV、重试次数持久化。
- 重新上电使旧 PIN token 失效。
- CredentialManagement 枚举和删除。
- 等待 UP 时 Keepalive/CANCEL，以及取消后的正常请求。
- 官方用户在场 HTTP 入口；空闲触摸拒绝。
- Reset 超过十秒拒绝、重新上电后恢复窗口，Reset 清空 PIN/凭据。

每项测试使用独立的合成 Flash 文件，每轮报告写入
`build/virtual-hid/runs/run-*/result.json`。不会读取真机或真实凭据。
首次验证：九项核心测试 14.91 秒；十项 HID 回归 18.28 秒。下载/构建耗时另计。

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

本地工具版本 1.9.3.1，原 Electron 为 41.7.0。包内只有 Mac/Windows 安装程序。
`prepare_official.py` 按字节复制运行源码与测试模块到忽略目录，并记录哈希；不复制
`.env`、签名配置或 Mac 原生依赖。`official.Dockerfile` 提供同版本 Electron 和
相同版本的顶层依赖，原生模块针对 Linux 重建。测试源码和 HID 实现不做修改。

官方自动化接口依据：
[FIDO Automation.md](https://github.com/fido-alliance/conformance-test-tools-resources/blob/main/docs/FIDO2/Automation.md)。

```sh
python3 host/virtual/run.py official
```

该命令准备 `ohmykei-conformance` 专用容器，在 Xvfb 中启动干净的原版 Electron
会话，以 CDP 配置并执行 CTAP 2.3 Generic/GetInfo、PIN 1/2 密钥协商最小集合。
每轮使用空的合成 Flash 和独立 Electron 配置目录；运行结束停止该会话的虚拟设备、
Electron 和 Xvfb。它不置前 macOS 窗口、不注入键鼠，不修改官方测试或 Mocha。
官方会话禁用自动触摸，只由 `/conformance/userpresence` 驱动 UP。

固定测试元数据位于 `host/virtual/metadata.json`；空库容量期望为 64，来自项目的
容量契约，不能用当次 GetInfo 响应自动生成期望值。运行报告位于
`build/virtual-hid/official/session-*/smoke-result.json`。
这是选定的官方最小回归，完整 CTAP 2.3 套件仍需单独执行和记录。

2026-11-04 已完成一键验收：官方最小集 **5 通过、2 能力不适用跳过、0 失败**，
运行器耗时 6.622 秒。对应 GetInfo 的两个跳过项为可选的 `encIdentifier` 与
`encCredStoreState`。官方测试、断言、HID 实现和 Mocha 均未修改。
自有完整入口同时通过 9/9 核心测试和 10/10 HID 回归（分别 14.98 和 18.197 秒）。

依赖镜像发生变化时，启动脚本停止并重命名旧的专用容器，保留它后创建匹配镜像的
新容器；不会删除旧容器。`stop` 会停止当前两个专用容器。

## 覆盖边界

此路径执行真实协议与密码学代码，并使用实际 Linux HID 栈。Flash 模型保留
256 字节页对齐、4 KiB 扇区和 NOR 1→0 约束，写入完成前同步文件。
重新上电保留 Flash、清空易失状态；使用单调实时时钟，保留超时语义。
它不模拟 RP2350 指令、TinyUSB/USB 控制器、硬件随机源或真实 Flash 时序。
当前 dev 阶段不引入 OTP 熔丝、boot 锁定或刷写操作。
