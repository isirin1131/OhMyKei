# OhMyKei 技术债审计与修复记录

日期：2026-11-03  
工作目录：`/Users/zhecai/OhMyKei`

## 1. 当前任务边界

- 用户最初要求：先找技术债和可能成为技术债的部分，不急着推进实现；历史审计阶段保持只读，不修改源码、测试、构建配置或文档。
- 现状更新（2026-11-03）：用户已明确要求执行修复。本轮已按要求实施代码与配置级修复，除记录修复状态外，仍遵守不擅自扩大修改范围、不提交、不清理仓库等工程纪律。
- 必须区分：已确认缺陷、当前设计债、条件触发/未来债、另一份报告中的错误或过度表述。
- 另一 agent 的报告和 Antigravity 后续输出都只是待核实证据，不能直接接受其结论。
- 当前验证结果：host 12/12 通过、fw-release `layout-check` 通过；本机因 Apple clang 缺 libFuzzer runtime，未运行 fuzz，只有 CTAPHID 确定性 replay 覆盖。
- 第 2–4 节保留审计时的证据与判断，不代表所有条目仍未修复；逐项处置状态以第 5 节为准。

## 2. 审计时确认的技术债（历史快照）

### P0：安全和可恢复性基线

1. **[未解决] 核心实现大多未进入 Git**
   - 审计时仓库总共只有 13 个跟踪文件，核心源码、测试、链接检查和实现文档大多未跟踪，工作区有 22 条变更记录。
   - 风险：无法可靠 review/blame/bisect；`git clean -xdf` 会删除核心实现。
   - 这是工程可恢复性风险，不是代码逻辑缺陷。

2. **[未解决/发布阻塞] RNG 不符合项目声明的 CSPRNG/故障传播契约**
   - `src/platform/platform.c:39-66` 使用 `get_rand_32()` 并无条件成功；`src/omk_port.h:26-29` 要求密码学安全随机数。
   - Pico SDK 使用 xoroshiro128** 软件 PRNG，每次 `get_rand_64()` 也混入新 TRNG 样本；TRNG 健康检查被关闭，接口没有向适配器暴露熵源故障。
   - 准确结论：无法发现熵源故障却始终报告成功；不能仅凭 xoroshiro 可逆就断言当前私钥可被恢复。

### P1：协议、状态和可用性缺陷

3. **[已修复] 四处错误默认 `pinUvAuthProtocol = 1`**
   - `src/fido/omk_ctap_auth.c:593-603`（MakeCredential）
   - `src/fido/omk_ctap_auth.c:1143-1152`（GetAssertion）
   - `src/fido/omk_ctap_mgmt.c:99-108`（CredentialManagement）
   - `src/fido/omk_ctap_pin.c:717-733`（ClientPIN）
   - CTAP 2.3 相应算法要求：有 `pinUvAuthParam`、缺协议字段时返回 `CTAP2_ERR_MISSING_PARAMETER`。
   - 注意：`hmac-secret` 扩展内部缺省协议 1 是另一项规范规则，不能机械替换所有默认值。

4. **[已修复] 请求的 `credProtect` 未在 MakeCredential 响应中回显**
   - `src/fido/omk_ctap_auth.c:498-516` 的 `build_mc_ext_map()` 只生成 hmac-secret 输出。
   - 规范：请求了 credProtect 时返回实际采用值；未请求时不得主动回显。
   - host 测试中没有 `credProtect`/`cred_protect` 用例，但 `docs/IMPLEMENTATION.md:49` 将其列入覆盖范围。

5. **[已修复] 删除凭据后继续枚举会使用过期数组下标**
   - 枚举保存 `store.creds[]` 下标：`src/fido/omk_ctap_mgmt.c:225-247`。
   - 删除会前移 RAM 数组：`src/fido/omk_store.c:647-655`。
   - 删除未清理枚举状态：`src/fido/omk_ctap_mgmt.c:387-415`；dispatcher 对所有 `0x0A` 保留状态：`src/fido/omk_ctap.c:360-364`。
   - “开始枚举 → 删除 → next”可能跳项、返回错误项或报状态错误。现有测试只有单条凭据，没有覆盖 continuation。

6. **[已修复] 撕裂/部分写入后，同次上电重试会持续命中脏槽**
   - meta：`src/fido/omk_store.c:339-346`；credential log：`src/fido/omk_store.c:789-797`。
   - 触发条件必须保留：失败已经在目标槽留下非空白内容；不是所有瞬时写错误都必然触发。
   - 已提交数据不会因这个机制被破坏，但同次上电写入可能持续失败，重启扫描后才能跳过。
   - 现有测试验证失败后重启恢复，没有验证同次上电继续写入。

7. **[已实施协作轮询；硬件时序未测] 长 Flash/密码学操作期间无法及时 KEEPALIVE/CANCEL**
   - compaction 同步擦除并回读整个 496 KiB bank：`src/fido/omk_store.c:804-825`。
   - Reset 同类操作：`src/fido/omk_store.c:1201-1217`。
   - USB pump/KEEPALIVE 只在触摸等待：`src/fido/omk_ctap.c:57-86`。
   - 结构上无法在这些同步操作期间处理传输；实际宿主超时时长仍需硬件测量，不能声称已测得超时。

8. **[AAGUID 已修复；USB PID 未解决] AAGUID 生命周期错误，USB PID 未分配**
   - AAGUID 在格式化和 Reset 时随机重生：`src/fido/omk_store.c:1060-1068`、`:1226-1228`。
   - CTAP 定义 AAGUID 标识认证器型号，同型号应一致，不应每设备/每次 Reset 改变。
   - `src/platform/usb_descriptors.c:16-18` 使用 `2E8A:10A1`；Raspberry Pi 官方 PID 表将 `0x10A1` 标为 unallocated，发布前必须解决。

### P2：中等优先级工程债

9. **[已修复] 存储错误码压缩**
   - MakeCredential 将容量、Flash、压缩等失败都报 `KEY_STORE_FULL`：`src/fido/omk_ctap_auth.c:786-788`。
   - updateUser 持久化失败可报 `NO_CREDENTIALS`：`src/fido/omk_ctap_mgmt.c:466-472`。

10. **[已修复] compaction 的敏感栈副本未清零**
    - `src/fido/omk_store.c:859-867` 的局部 `meta_image` 含 master key/PIN hash，成功和失败返回都未 wipe。

11. **[未解决] RX 丢包不一定有重组超时兜底**
    - `src/platform/platform.c:200-209`：首帧/单帧命令被丢时没有活动重组可超时；后续续帧也会成为游离帧。
    - TX/RX drop counters 只有 accessor，没有固件消费者。

12. **[已修复] CredentialManagement 裸写绕过 CBOR 容量检查**
    - `src/fido/omk_ctap_mgmt.c:274-276`、`:337-339` 直接 `e.buf[e.len++] = ...`。
    - 当前容量足够，属于增长后可能溢出的现时脆弱点，不宣称当前可溢出。

13. **[harness 已改；fuzz 未运行] 没有命令层 fuzz**
    - `host/fuzz_ctaphid.c:118-125` 的 handler 是桩，不调用 `omk_ctap_handle`。
    - 通用 CBOR/CTAPHID 重组 fuzz 不等于 MC、GA、ClientPIN、CredentialManagement 状态机 fuzz。

14. **[未解决] 持久化格式演进成本高**
    - 当前只接受精确 meta v2，无迁移；字段分散在结构、offset、序列化、解析和双向复制多套手工列表。
    - 风险是出货后的升级路径，不是当前会自动清设备。

15. **[部分修复] 构建、验证和秘密卫生**
    - 核心源列表在根 `CMakeLists.txt:129-141` 与 `host/CMakeLists.txt:22-34` 重复（已统一到 `cmake/core-sources.cmake`）。
    - CTAPHID 版本仍硬编码于 `src/fido/omk_ctaphid.c:500-502`；CI 已新增 host/fuzz，但尚无远端执行结果。
    - `tools/fido-conformance/fast_downloader.py:13-17` 曾有硬编码 HTTP Basic 凭据（已改为环境变量注入）；未证明已泄露，私有凭据轮换仍需负责人完成。

## 3. 审计时的条件触发/未来债

- 单线程下可接受、并发化后会成为竞态的静态/懒初始化状态：
  - `src/fido/omk_ctap.c:359` 静态 CBOR doc；
  - `src/crypto/p256.c:485-493` generator；
  - `src/crypto/aes.c:39-66` rsbox。
- PIN/UV 两套加解密：`src/fido/omk_ctap_pin.c:250-381` 与 `src/fido/omk_ctap_auth.c:94-238`，扩展时易漂移。
- `OMK_CTAP_PIN_PROBE/ABORTED` 带内哨兵：`src/fido/omk_ctap_internal.h:8-9`；当前有防逃逸测试，新增命令可能漏翻译。
- 不可传播错误的 API：HKDF 超长静默截断 `src/crypto/sha256.c:244-264`；CBC 非法长度静默返回 `src/crypto/aes.c:236-245`。当前调用长度受控，属于未来债。
- 测试耦合/独立锚点不足：store 测试直接操纵内部表示；hmac-secret 测试用生产函数生成期望值；P-256 向量 provenance 未完整记录，不能无证据断言全是自生成。
- `57/59` 分片魔数、未使用 TX timeout、测试数量硬编码、陈旧 APDU/CDC 注释属实，但优先级低。

## 4. 对另一份报告的纠偏（审计时结论）

- RNG：问题成立，但“私钥可直接反推”证据不足；SDK 每次输出也混入新 TRNG 样本。
- 未知存储版本：当前 fail-closed，不会自动清空；问题是无法初始化和没有迁移路径。
- 超过 64 条静默丢弃：仅异常/外部构造日志加载路径；正常公开 API 会在第 65 条写入前拒绝。
- `check_layout.cmake` 的地址字面量可作为独立断言，且另有编译期区域检查，不是高优先重复。
- pico-sdk 精确钉版与 vendored linker fragments 匹配，是有意约束。
- LICENSE 头、CHANGELOG、格式化配置不是与协议/安全缺陷同级的技术债。
- USB PID 已进一步确认是 unallocated，不再只是待确认。

## 5. 执行结果

### 5.1 验证结果

- **host 全量**：`ctest --preset host --output-on-failure` 12/12 通过。
- **固件**：`cmake --build --preset fw-release --target layout-check` 通过（32 KiB 栈，镜像低于存储区上界）。
- **fuzz**：本机未运行。Apple clang 缺 libFuzzer runtime，`cmake --workflow --preset fuzz` 在配置阶段失败；只有 `test_fuzz_ctaphid_replay` 通过。
- **CI**：工作流已添加，但尚无远端执行结果，不能算验证通过。

### 5.2 已实施项

1. **四处 pinUvAuthProtocol 缺省**：修复 MakeCredential、GetAssertion、CredentialManagement、ClientPIN 中缺协议字段时返回 `CTAP2_ERR_MISSING_PARAMETER`，并有精确回归测试。
2. **credProtect 回显**：请求时回显实际采用值，未请求时不主动回显，并校验回显值与密封凭据一致。
3. **删除后枚举（凭据和 RP 两类 continuation）**：凭据用稳定 `seq`，RP 跳过已删除的中间项；两类都有端到端回归。
4. **同次上电脏槽重试**：撕裂或写入失败后推进游标，保护唯一有效 meta 扇区；host 测试覆盖 meta 与凭据日志。
5. **长操作协作取消**：compaction/Reset 在非活动 bank 的安全边界处理 USB/KEEPALIVE/CANCEL，meta 提交后不再取消；不声称已测真实硬件时序。
6. **固定型号 AAGUID**：不再随格式化或 Reset 重生，旧设备在加载时迁移为固定型号值。
7. **存储错误分类**：区分容量满、取消与 Flash/序列化失败，不再统一报 `KEY_STORE_FULL` 或 `NO_CREDENTIALS`。
8. **compaction 敏感栈清零**：包含密钥和 PIN hash 的局部状态在成功和失败路径均清零。
9. **CBOR raw 容量检查**：CredentialManagement 的 COSE key 改为带边界检查的 `omk_cbor_put_raw`。
10. **CMake 核心源去重**：根目录与 `host/` 统一引用 `cmake/core-sources.cmake`。
11. **CI host/fuzz**：已新增 Ubuntu 工作流和 libFuzzer runtime 安装；未执行，见 5.1。
12. **conformance 凭据改环境变量**：硬编码凭据已移除，改为 `FIDO_CONFORMANCE_USERNAME/PASSWORD`；历史凭据轮换仍需负责人完成。
13. **fuzz harness 真实调用 omk_ctap_handle**：命令层 harness 已接入真实 CTAP/store 状态机；因本机无 runtime，未完成 libFuzzer 实跑。

### 5.3 仍然阻塞/未解决

1. **核心代码是否入库（本轮未 git add/commit）**：核心实现文件仍停留在工作区未跟踪/未提交状态，等待后续统一决定入库策略。
2. **RNG 熵源健康与故障传播（仅记录为发布阻塞）**：当前平台层尚未暴露熵源故障且 TRNG 健康检查未启用，列为正式发布阻塞项。
3. **USB PID 未分配（仅记录）**：Raspberry Pi 官方 PID 表中仍为 unallocated，正式发布前需分配官方正式 PID。
4. **持久化格式迁移未做**：目前仅支持单一元数据格式，尚未实现出货升级所需的存储版本平滑迁移机制。
5. **RX 首帧/单帧丢失无法由接收端兜底**：物理/传输层丢帧在无活动重组上下文时无法单靠接收端超时机制兜底。
6. **实际硬件长操作时序未测量**：Flash 擦除与大容量搬移的真实硬件耗时及 USB 宿主超时边界仍需在真机上实测。
7. **私有 conformance 凭据轮换需负责人执行**：历史代码曾包含私有凭据，轮换操作需具有权限的负责人手动完成。
8. **fuzz 本机因 AppleClang 缺 libFuzzer runtime 未运行（host replay 通过，CI 已加运行时安装）**：本机环境受编译器 runtime 缺失限制未实际运行 fuzz；host replay 用例已通过，CI 环境已配置对应运行时。

## 6. Antigravity 官方子代理调用方式

### 已验证环境

- 用户自己安装的 CLI：`/Users/zhecai/.local/bin/agy`，PATH 中可直接用 `agy`。
- 版本：`1.4.12`。
- 用户指定模型：`gemini-3.8-flash-high`（slug 已包含 High，无需另加 `--effort high`）。
- 不重装、不删除用户的 CLI；临时文件不得留在仓库或用户目录。

### 通用调用模板

```bash
agy -p '独立、具体的子任务说明。只读审查，不调用工具，不修改文件。' \
  --model gemini-3.8-flash-high \
  --output-format json \
  --print-timeout 5m
```

需要读取代码时，可允许其只读工具，但 prompt 必须明确“不得修改文件、不得运行写入/构建命令”。不要使用 `--dangerously-skip-permissions`。

成功 JSON 示例字段：`status:"SUCCESS"`、`response`、`conversation_id`、`usage`、`duration_seconds`。解析时同时检查进程退出码和 JSON `status`，不能只看 stdout。

### DSH 沙箱注意事项

- `agy` 需要读取 macOS 钥匙串登录态，并写入 `~/.gemini/antigravity-cli` 的日志/会话数据库。
- 在 DSH `workspace-write` 下会出现 home 目录写入拒绝；实际调用应使用 `sandbox_permissions: "danger-full-access"`，并给出仅限上述原因的批准说明。
- 这是让官方 CLI 访问自身配置，不是给子任务额外写权限；仍保持默认 permission mode，不加危险跳过参数。
- 若返回 `RESOURCE_EXHAUSTED/429`，如实报告账号额度，不重试轰炸、不切换未授权模型。
- 官方 Python SDK 已验证要求 `GEMINI_API_KEY` 或 Vertex/企业配置，不能直接使用账号订阅 Plan；当前优先使用 CLI，不再次安装 SDK。

## 7. 后续维护约定

- 新发现的缺陷继续追加“证据、影响、触发条件”，不要把审计推断写成已复现事实。
- 代码变更后至少复跑 host 测试与固件 `layout-check`；fuzz 只有在实际执行后才能记为通过。
- 子代理输出仍需独立读码/规范复核，不能直接并入“已确认”。
- 未完成的发布决策（RNG、USB PID、存储迁移）应保持显式阻塞，不用文档表述掩盖。
