# RoboLink · 机器人调试台

RoboLink 是运行在 Linux 开发机上的桌面 GUI，用 SSH 管理 Linux 机器人。目标拓扑是开发机与机器人用一根以太网线直接相连，不经过路由器或交换机；机器人内部 Wi‑Fi 是独立的远端控制对象。

## 版本状态

当前源码版本为 **v0.3.0 测试候选**。这一版新增多网口 ARP 被动发现、设备候选 IP/MAC/网卡标注，以及用户确认后给开发机物理有线接口添加和清理临时 IPv4 地址的流程。尚未完成真实硬件验收，**没有创建 GitHub Release**；收到测试包后请先在自己的 Ubuntu 22.04 机器人上验证，再决定是否发布。

## 主要功能

- 通过 SSH 管理多个 Linux 机器人。首次连接需经可信渠道核对 SSH 主机指纹；后续指纹变化会阻断连接。
- 同时监听所有已连接的物理有线网口 8 秒，展示 ARP 源 IP、MAC、来源网卡和证据类型；只探测用户选择的单个 TCP 端口（默认 22），且仅当系统路由指向该直连接口时报告端口状态。
- 可在明确确认后给选定的开发机有线网口增加一条临时 IPv4。授权 helper 会检查地址格式、重复地址和重叠路由；默认在 SSH 会话结束时清理，也可以选择保持并手动移除。
- 通过已验证的 SSH 连接读取机器人概览、systemd 服务、NetworkManager Wi‑Fi、BlueZ 蓝牙、PipeWire/PulseAudio 默认音频设备与音量，以及 ALSA 硬件 PCM 端点。
- 提供 SSH 交互终端、高风险命令确认、多行粘贴预览、本地诊断记录和浅色/深色模式。

RoboLink 不提供 DHCP server、不猜测任意静态 IP、不自动修改机器人端网络，也不会替开发机改 Wi‑Fi、DNS、默认网关或防火墙。ARP 只是一种发现证据：不发 ARP 的静默设备可能无法扫描到；MAC/IP/TCP 端口也不能替代 SSH 身份核验。

## Ubuntu 22.04 安装

请使用项目维护者提供的 `RoboLink_0.3.0_ubuntu22.04_amd64.deb` 测试候选包，不要从不明网站下载，也不要把它当作正式 GitHub Release。下载后可在 Ubuntu 文件管理器里双击 `.deb`，使用“应用中心/软件安装”打开并点击“安装”；也可以运行：

```bash
sudo apt install ./RoboLink_0.3.0_ubuntu22.04_amd64.deb
```

然后从系统应用列表启动 **RoboLink**。开发机和机器人之间的连接步骤、授权说明和故障排查见[第一次直连 Linux 机器人操作手册](docs/first-direct-connection.md)。

测试包以 Ubuntu 22.04 amd64 为构建目标，最高要求 GLIBC 2.34。其他发行版或 CPU 架构需要单独构建和验证。应用依赖 Ubuntu 桌面版的 WebKitGTK 4.1（至少 2.38）、GTK、OpenSSH、iproute2 和 polkit；机器人端不需要安装 RoboLink。若安装器提示 WebKitGTK 版本不足，请先用“软件更新器”安装 Ubuntu 22.04 更新，或运行 `sudo apt update` 后重试，不要从不明网站单独下载系统库。

## 从源码运行与构建

需要 Node.js/npm、Rust/Cargo，以及 Tauri Linux 开发依赖（Ubuntu 22.04 可安装 `libwebkit2gtk-4.1-dev`、`build-essential`、`curl`、`wget`、`file`、`libxdo-dev`、`libssl-dev`、`librsvg2-dev`、`libayatana-appindicator3-dev`）。浏览器模式仅为界面演示，不会连接真实机器人。

```bash
npm install
npm run dev           # 浏览器 UI 演示
npm run app:dev       # Tauri 桌面程序
npm run app:build     # 构建 Debian 安装包（只构建 .deb）
npm run test:rust     # 构建 helper，并运行主应用和 helper 的 Rust 测试
npm run build         # TypeScript + Vite 前端生产构建
```

建议在 Ubuntu 22.04 或等价的 Jammy 容器中构建；在较新的发行版构建可能抬高所需 GLIBC 版本。`app:build` 会先单独构建受限网络 helper，并将其随 Debian 包安装；helper 仅在用户确认网络操作时由系统授权窗口调用。不要手动把它改成宽泛的 root shell 或让整个 GUI 以 root 身份运行。

## 项目目录

```text
src/                              React + TypeScript 界面
src-tauri/                        Tauri 2 桌面壳与 Rust SSH/设备后端
net-helper/                       独立、参数受限的 Linux 网络授权 helper
docs/product-spec.md              产品、安全与功能规格
docs/first-direct-connection.md   Ubuntu 安装和直连网络新手手册
```

浏览器界面预览只展示视觉设计，不表示真实设备状态：

![RoboLink 深色模式设计预览](./ui-preview.png)

![RoboLink 浅色模式设计预览](./ui-preview-light.png)
