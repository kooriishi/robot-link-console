# RoboLink · 机器人调试台

RoboLink 是运行在 Linux 开发机上的桌面 GUI，用 SSH 管理 Linux 机器人。目标拓扑是开发机与机器人用一根以太网线直接相连，不经过路由器或交换机；机器人内部 Wi-Fi 是独立的远端控制对象。发现、选择策略、配置临时地址、启动/停止 DHCP 和建立 SSH 连接都在图形界面中完成，不提供面向用户的发现 CLI。

## 版本状态

当前版本为 **v0.4.3**。本版为机器人端服务、Wi-Fi 开关和蓝牙变更加了一次性 sudo 授权：非交互操作在确认后短暂输入密码，密码只经 SSH 加密连接的标准输入发送，不写入命令参数、配置文件或诊断记录。Wi-Fi 连接和蓝牙配对等需要交互的操作仍在 SSH 终端提示 sudo 密码及系统要求的 Wi-Fi 密码/配对确认。切换 Wi-Fi 前只为当前 SSH 客户端添加运行期 /32 或 /128 有线回程路由，不改默认路由和 DNS，机器人互联网流量仍按 Wi-Fi 默认路由。

当前自动化覆盖主应用 18 项、网络 helper 25 项 Rust 单元测试，TypeScript/Vite 生产构建通过。Debian 包在 Ubuntu 22.04 (Jammy) 用户空间构建，已检查控制信息、归档文件、可执行文件及动态库（无缺失依赖，最高 GLIBC 2.34）；尚未进行真实机器人硬件验收。

## 可选设备发现策略

| 策略 | GUI 中的选择与行为 |
|---|---|
| A0 · 主动 ARP 扫描（默认开） | 以 `0.0.0.0` 为源地址发送 RFC 5227 ARP 探测，Linux 开发板会为自己配置的 IP 应答。覆盖本机网段及约 30 个常见开发板 /24（192.168.1/0/127/137/55、10.42.0 等）；“深度扫描”另覆盖整个 `192.168.0.0/16` 与 `169.254/16`，约 5 秒发完。承载默认路由的接口（接了路由器/局域网）只扫描本机所在网段。 |
| A · 被动发现 | ARP Request/Reply、Gratuitous ARP、ARP Probe；DHCP Discover/Request；IPv6 Neighbor Discovery；mDNS 报文源地址。分别选择，展示接口、IP、MAC 与证据。 |
| B · 主动验证 | 对已知候选进行定向 ARP、可选 ICMP 和指定单个 TCP 端口验证，默认 SSH 端口 22，可自定义。不会遍历任意子网或端口范围；Ping 失败不等于设备离线。 |
| C · DHCP 发现 | 默认不启动。用户选择物理有线接口并确认后，启动本应用专属、单接口 DHCP Server；仅供直连 SSH，不下发默认网关和 DNS、不共享 Internet。可查看状态、停止并清理自身配置；自身 DHCPACK 日志仅提供待复验的缓存候选。 |
| D · Link-local | IPv4 `169.254/16` 的报文/邻居候选与 IPv6 Link-local 发现。IPv6 地址携带 `%网卡名` scope，贯穿验证和 SSH 连接；不会穷举整个 `/16`。 |

以被动、低干扰方式优先收集证据；B 类主动验证仅限候选地址，IPv6 Link-local 可选策略另有受限全节点探测。可以选择所有物理有线接口或指定接口，每个候选保留对应网卡。断开的接口会跳过，不让其他接口的扫描一起失败。物理链路统一读取内核 carrier 状态，不再错误依赖 sysfs `flags` 中并不可靠的链路位。

ARP Probe、DHCP 请求地址、IPv6 DAD 和邻居缓存都是不同强度的候选证据。一般 ARP 请求中的目标 IP 不会被当作对端地址；缓存也不证明当前接入的是原设备。**任何策略都不能保证发现任意静默的未知静态 IP，IP/MAC/TCP 可达也不能替代 SSH 身份核验。**

## 主要功能与安全边界

- 多目标 SSH 管理、首连主机指纹核验和后续密钥变化阻断；支持自定义用户名和 SSH 端口。
- 用户明确确认后，为选定物理有线网口附加一个临时 IPv4。添加前检查地址、路由重叠和重复地址；默认在 SSH 会话结束时清理，也可保持并手动移除。ARP 不携带掩码，普通地址的 `/24` 只是可编辑假设。
- DHCP 由独立受限 helper 管理，只清理本应用记录的服务和地址，不终止系统原有 dnsmasq，不删除用户 NetworkManager 连接。应用异常退出后，可查询并清理 `/run` 中的自身记录。
- 授权未完成/取消、授权代理或 helper 启动失败、授权后的网络操作失败分开显示；不把所有失败都说成“授权失败”。
- 通过已验证 SSH 读取机器人概览、systemd、NetworkManager Wi-Fi、BlueZ、PipeWire/PulseAudio 和 ALSA 硬件 PCM 清单。
- 交互终端、高风险命令确认、多行粘贴预览、本地诊断记录和浅色/深色切换。

整个 GUI 不以 root 运行。机器人端需要提权的服务、Wi-Fi 和蓝牙变更在用户确认后使用一次性 sudo 密码；密码不会保存或写入应用日志。切 Wi-Fi 时，RoboLink 只在机器人内存路由表里为当前 SSH 客户端加一条精确主机路由，经原有有线接口回包；不覆盖已存在的不同静态路由，也不改默认路由、DNS、机器人 IP 或防火墙。Wi-Fi 开启并联网时，其他流量仍可走 Wi-Fi。DHCP 仅适用于你确认的一根网线直连，不应在办公网络或共享 LAN 上启动。当前不实现电脑向机器人共享 Internet；机器人 DHCP 和路由行为仍需实机验证。

## Ubuntu 22.04 安装与试用

收到 `RoboLink_0.4.3_ubuntu22.04_amd64.deb` 后，在 Ubuntu 文件管理器里双击，用“应用中心/软件安装”打开并点击“安装”，然后从系统应用列表启动 **RoboLink**。无需在机器人端安装 RoboLink。详细图形界面操作见[第一次直连 Linux 机器人](docs/first-direct-connection.md)。

测试包以 Ubuntu 22.04 amd64 用户空间构建，最高要求 GLIBC 2.34。需要 WebKitGTK 4.1 至少 2.38、GTK、OpenSSH、iproute2、polkit、iputils-ping 和 dnsmasq-base；dnsmasq-base 提供受限 DHCP 使用的二进制，不代表 RoboLink 会默认启动 DHCP 服务。若桌面安装器提示依赖不足，请先使用 Ubuntu“软件更新器”，不要从不明网站单独下载系统库。其他发行版/CPU 架构需要单独构建与验证。

## 开发与构建

以下仅供项目开发，不是用户发现设备的操作流程。需要 Node.js/npm、Rust/Cargo 和 Tauri Linux 开发依赖。浏览器入口是视觉演示，不会连接真实机器人。

```bash
npm install
npm run dev           # 浏览器 UI 演示
npm run app:dev       # Tauri 桌面程序
npm run app:build     # 构建 Debian 候选安装包
npm run test:rust     # 主应用和受限 helper 的单元测试
npm run build         # TypeScript + Vite 生产构建
```

应在 Ubuntu 22.04 或等价 Jammy 用户空间构建，避免抬高 GLIBC 要求。helper 必须由系统包管理器安装为 root 所有、普通用户不可改写；源码开发模式不会启用不安全的本机提权。不要把它改成通用 root shell，也不要以 root 启动整个 GUI。

## 项目目录

```text
src/                              React + TypeScript GUI
src-tauri/                        Tauri 2、SSH 与发现策略编排
net-helper/src/main.rs            受限抓包、ARP 验证和本机地址操作
net-helper/src/dhcp.rs             单接口 DHCP 生命周期与所有权
scripts/                          构建脚本
docs/product-spec.md             产品、安全与功能规格
docs/first-direct-connection.md  GUI 安装和直连试用指南
```

现有总览视觉预览不代表真实设备状态，也不作为本次策略验收证据：

![RoboLink 深色模式设计预览](./ui-preview.png)

![RoboLink 浅色模式设计预览](./ui-preview-light.png)
