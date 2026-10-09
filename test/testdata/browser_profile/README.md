# 浏览器对照回归

这组数据来自真实 Chrome 的字节采集，不是把 Moto 常量复制成期望值。
它验证固定场景下的有限字段，不证明完整浏览器等价、抗识别或速度提升。

## 已覆盖的 H2 场景

- Chrome for Testing **133.0.6943.141**，macOS arm64，完整浏览器有界面模式。
- 三次独立浏览器会话，临时用户目录；没有覆盖 UA、TLS 或 HTTP/2 参数。
- 拒绝场景：经 loopback HTTPS 代理发送首个、未认证的 `CONNECT baseline.invalid:443`，
  返回 **502**。这是有意拒绝，不代表成功建立隧道。
- 域名/复用场景：外层 TLS SNI 为 `proxy.baseline.invalid`，顺序访问两个测试域名，
  在同一条物理 H2 连接的不同 stream 上建立隧道，再通过隧道完成内层 TLS 和 HTTPS GET。
  服务端记录请求、连接与 stream ID；客户端核验两个完整响应正文，不把返回 200 当成传通。
  载荷是小型固定 HTML，仅验证隧道完整性，不是大文件、吞吐或弱网性能测试。
- 认证场景：使用公开测试凭据。记录 Chrome 首个目标的 407 挑战及重试，再验证第二个目标
  的首次 CONNECT 已携带缓存凭据。Moto 使用生产路径预先发送认证，不人为制造 407。
  Chrome 可能为首个目标发送多次未认证请求；本次固定样本为两次，原始顺序完整保留。
- 所有成功场景只允许两个明确的测试 authority；源站在进程内终止，不解析或连接外部目标。
  Chrome 的后台请求仍可能出现，会被 403 拒绝并保留证据，但不混入测试目标的认证序列。
- 证书仅通过该浏览器进程的测试证书 SPKI 白名单放行；不修改系统信任或 Moto 校验。
- 固定启动参数限制后台联网、外部域名解析并禁用 QUIC；成功场景仅将测试代理域名映射到 loopback。完整有效参数、浏览器版本、
  可执行文件/下载包 SHA-256、采集时间及原始数据摘要保存在样本中。

拒绝场景三次采样的 11 组归一化字段一致。与 Moto 对照时，10 组相同，1 组存在明确差异：
Chrome 样本的 ALPS 扩展编号为 `0x4469`，当前 uTLS 模板为 `0x44cd`。
此差异保留在 `h2-known-differences.json`，只放行完整、精确的这一对值，
不会忽略整个 TLS 扩展检查。模板或浏览器发生变化时，必须重新审查，不可自动更新白名单。
这也不能推断所有 Chrome 133 平台、渠道或试验参数都产生同样字节。

新增成功场景还保留了 **HPACK 表示类别**：Chrome 的 CONNECT method 不加入动态表，
Moto 的编码策略不同；第二次 CONNECT 的动态索引及表大小更新也有差异。
认证场景首次成功请求的压缩上下文尤其不同：Chrome 此时已发送过挑战请求，Moto 则是预先认证。
这些差异被明确记录，**没有修改生产行为去凑齐样本**；没有把首次认证与缓存认证混为一谈。
各场景的 `*-known-differences.json` 只允许人工审查过的完整值对，仍会阻止其他新增差异。

归一化仅替换 TLS GREASE 值、排序随机排列的扩展编号；保留其他已列字段的顺序、
GREASE 位置/数量、key share 的组与长度。排除随机数、session ID、密钥内容、
padding 和未列出的扩展内容。H2 SETTINGS、窗口更新和请求头名称按实际顺序比较。
成功场景额外比较首个/第二个成功 CONNECT 的 HPACK 表示类别，但不比较完整编码字节、
Huffman 选择、动态索引具体数值或长期动态表演变。

未覆盖：会话恢复、HRR、跨站分区/复杂认证流程、并发大量 stream、
完整 HPACK 行为、TLS record 分包、数据传输时序、拥塞与长期流量统计特征。
CI 的 Linux Moto 与这份 macOS Chrome 样本比较，不等于另外采集了 Linux Chrome。

## H3 的真实限制

Chrome 133 官方发布版使用 `quic://` 代理时，本次实测返回
`ERR_NO_SUPPORTED_PROXIES`；本地 UDP 夹具收到 **0** 个数据报。
[该版本 Chromium 构建配置](https://github.com/chromium/chromium/blob/133.0.6943.141/net/features.gni)
默认只在 debug 构建启用 QUIC proxy 支持。运行参数不能补回未编译的功能。

因此没有 `chrome-133-h3.json`，也没有给 H3 建立“浏览器一致”通过门禁。
H3 采集夹具已提供，Moto 的实际握手与 CONNECT 可采集；缺少浏览器同场景证据时
会失败并保留诊断。没有把浏览器的普通 H3 GET 当成代理 CONNECT 样本。
现有 H3 wire tests 仍是模板不变量测试，不能升级为真实 Chrome 对照结论。
H3 依赖使用自定义 ChromeParrot ClientHello，源码没有证明其对应 Chrome 133。
HTTP/3 SETTINGS 与 QPACK 不在本次修改范围。

## 重现

Go 使用项目锁定版本，Python 需要 3.11 或更新版。准备好 Go 工具链和模块缓存后，
常规门禁不安装/启动浏览器，不需要私人配置或外部代理，测试流量仅访问本机临时端口：

```sh
make browser-profile-check
```

重新采集需要自行取得[官方固定版本包](https://googlechromelabs.github.io/chrome-for-testing/133.0.6943.141.json)。
不要用过时浏览器访问外网；只用于这里的隔离 loopback 夹具。安装 Node.js 后：

```sh
python3 -B test/browser_profile_regression.py \
  --capture-chrome --protocol h2 --scenario all --samples 3 --headed \
  --chrome '/absolute/path/to/Chrome for Testing' \
  --chrome-source-url 'https://storage.googleapis.com/chrome-for-testing-public/133.0.6943.141/mac-arm64/chrome-mac-arm64.zip'
```

默认调用固定版本 `@playwright/cli@0.1.22`；也可用 `--playwright-cli` 指定本地 CLI。
所有会话独立命名并在结束时关闭，不接管已有浏览器。`--protocol h3 --samples 1`
可以重现缺口，但官方 133 预期不能完成，不能作为成功验收。
无头模式会真实发送 `HeadlessChrome` UA，不能冒充有界面样本，也不会偷偷覆盖 UA。

`--scenario` 默认为原拒绝场景；`h2_sni_reuse` 和 `h2_auth_reuse` 可单独采集，
`all` 运行全部三种 H2 场景。常规 `make browser-profile-check` 对每种场景运行三次 Moto 实测。
认证通过 Playwright 的 Chromium 代理挑战处理器提供凭据，不注入请求头；有效浏览器参数完整保留。

证据写入忽略的 `output/playwright/`：原始字节、浏览器日志、版本与完整参数、
JSON 对比结果。导入新基线必须人工确认三次样本稳定、版本和来源可信、
确实收到目标 CONNECT，且解释全部差异；不把失败/空样本提升为基线。
仓库只保存归一化样本和摘要，不包含浏览器程序、临时用户目录或私人流量。

比较器退出码：`0` = 已列字段一致或精确的已知差异；`1` = 新差异；
`2` = 缺失或无效证据。通过并不表示所有字段相同，更不表示观察者无法识别 Moto。
