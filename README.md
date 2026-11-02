# Claude 无法使用 · 分层自查模板（附只读扫描工具）

一个帮普通用户判断「Claude 打不开 / 用不了」发生在哪一层的自查项目：
**地区限制 / 账号状态 / 网络链路 / 浏览器 / 桌面客户端**。

> **边界**：本项目不提供、也不得用于绕过任何服务的地区限制或访问控制。
> 使用前请先确认 Anthropic 官方支持地区：https://support.claude.com/en/articles/8461763-where-can-i-access-claude
> 如果你实际所在地区不在列表中，结论就是「该地区不支持」，请勿尝试规避。

## 组成

- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** — 核心。按顺序填写的分层自查清单，含「报错 → 最可能原因 → 下一步」对照表。
- **scan/**（可选）— Windows 只读扫描脚本。一台电脑即可运行，采集本机网络与 Clash Verge / Mihomo 配置事实，输出两份 JSON 作为排查证据。不修改任何配置，不导出账号或密钥原文。
- **docs/** — 隐私说明、对比方法、已知限制。

## 适合谁

- Claude 网页一直停在 “Just a moment…”，或加载不出来
- 能开登录页，但登录循环、收不到验证码
- 能登录，但发消息失败 / 被登出
- 桌面客户端能用、浏览器不行（或反过来）
- 想确认问题是不是本机的代理 / DNS / TUN / 浏览器环境导致
- 换电脑 / 改配置后想留一份可对比的基线

## 不适合谁

- 想在不支持地区使用 Claude —— 本项目不提供方案
- 想备份或迁移完整 Clash 配置 —— 扫描器只读，不写配置、不包含节点凭据原文
- 非 Windows 用户 —— 系统网络采集器是 PowerShell（Clash 部分可跨平台单独运行）

## 快速开始

1. 打开 [TROUBLESHOOTING.md](TROUBLESHOOTING.md)，从第 1 步开始填。多数人到这里就能得出结论。
2. 需要更细的证据时，再运行 **scan/** 下的只读扫描。

扫描环境要求：Windows 10/11、PowerShell 5.1+、Python 3.9+（PyYAML 6.0.3 已随包提供，无需 pip）。

## 扫描工具：做什么 / 不做什么

**做：**

- 读取 Clash Verge / Mihomo 的实际配置目录、当前 profile、生成配置、规则、代理组、节点指纹
- 读取系统代理、WinHTTP / WinINET、环境变量、hosts、浏览器策略注册表、防火墙 profile 状态
- 5 轮连接探针（CONNECT / TLS / HTTP）与出口回显
- 输出 windows-network.json / clash-policy.json

**不做：**

- 不修改代理、DNS、路由、防火墙、Clash 规则或节点、浏览器、账号
- 不读取账号、Cookie、会话、订阅原文、证书私钥
- 不自动提权、不安装任何组件

## 报告安全提醒

报告不含节点密钥原文（只保留长度 + SHA256），但**会包含本机内网 IP、网关、网卡名、机器名、节点名称/端口/SNI、配置哈希**。

- 不要把报告提交到仓库或公开
- 分享给别人排查前先脱敏
- 注意：IPv4 地址的 SHA256 可以被暴力反推，不要把它当作匿名

## 目录结构

~~~
.
├── README.md
├── README.en.md
├── TROUBLESHOOTING.md
├── LICENSE
├── .gitignore
├── docs/
│   ├── PRIVACY.md
│   ├── METHODOLOGY.md
│   └── LIMITATIONS.md
└── scan/
    ├── README.md
    ├── Run-ReadOnlyScan.ps1
    ├── Collect-WindowsNetwork.ps1
    ├── collect_clash.py
    └── vendor/          # PyYAML 6.0.3 (MIT)
~~~

## License

MIT。scan/vendor 下的 PyYAML 6.0.3 为 MIT，许可证见 scan/vendor/PyYAML-LICENSE.txt。
