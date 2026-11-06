# RoboLink · 机器人调试台

RoboLink 是运行在 Linux 开发机上的无头机器人调试桌面应用。它支持经 SSH 管理 Linux 机器人，并为直接有线连接提供受限的接口发现。**有线拓扑是开发机和机器人一根网线直连，不经过路由器、交换机或中间设备。** 机器人 Wi‑Fi 是独立的远端控制对象。

## 版本状态

当前源码版本为 **0.2.2**，是待审的 Linux 候选版；它基于 v0.2.1，新增不依赖 PipeWire/PulseAudio 的 ALSA 硬件识别，并优化页面切换与终端排版。此任务没有接入实际机器人，因此真实硬件连接、无线配对和音频播放仍需你在自己的设备上验证。

## 当前功能

- 通过 SSH 管理多个 Linux 目标；首次连接显示主机密钥指纹，让用户选择并核对一把密钥后固定；变化时阻断连接。
- 在开发机物理有线接口上查看链路，并列出所选接口 Linux 邻居表中的 IPv4 地址候选；在受限子网内探测用户指定的单个 TCP 端口（默认 22）。扫描绑定到选中的接口；不会修改开发机 IP、默认路由或 DNS。
- 读取机器人概览、systemd 服务、NetworkManager Wi-Fi、BlueZ 蓝牙、PipeWire/PulseAudio 默认输入/输出设备与音量；另外读取 ALSA 硬件 PCM 播放/采集端点，即使机器人没有音频服务器也可显示识别结果。
- 提供交互式 SSH PTY 终端、高风险命令确认、多行粘贴预览、本地操作事件记录；已访问页面保留实例，终端缩放更新合并处理。
- 提供浅色/深色模式。

服务启停、机器人 Wi‑Fi、蓝牙配对/连接和音频设置会改变机器人状态，界面会要求确认；应用不自动提权。直连扫描可帮助发现 Linux 已记录的邻居 IP，但不能凭一根网线推导任意静态地址；两端仍需先有同网段 IP。邻居缓存也可能包含过期地址。详见[第一次直连操作手册](docs/first-direct-connection.md)。

## 下载与安装

v0.2.2 的 Ubuntu 22.04 amd64 `.deb` 是本地待审候选，尚未上传或发布。审阅通过后可从 GitHub Release 下载并安装：

```bash
sudo apt install ./RoboLink_0.2.2_ubuntu22.04_amd64.deb
```

系统会按 deb 包依赖检查桌面运行库。打开系统应用菜单中的 **RoboLink** 启动。应用运行在开发机上，机器人端不需要安装 RoboLink。

> 候选包按 Ubuntu 22.04 x86_64 用户空间构建。其他发行版/架构需自行验证 GTK/WebKitGTK 等桌面依赖兼容性；Windows、macOS 和 Linux ARM 构建不在此版本范围内。

## 从源码运行

需要 Node.js、npm、Rust/Cargo、Tauri Linux 开发库（GTK 3、WebKitGTK 4.1 等）。浏览器模式只用于界面演示，不会连接真实机器人：

```bash
npm install
npm run dev
```

运行真实桌面功能：

```bash
npm run app:dev
```

在兼容 Linux 环境构建 deb：

```bash
npm run app:build -- --bundles deb
```

## 主机工具

开发机需要 OpenSSH 客户端（含 `ssh`、`ssh-keyscan`、`ssh-keygen`）、`iproute2`（`ip`）。可用系统工具控制器件：NetworkManager 的 `nmcli`、BlueZ 的 `bluetoothctl`、音频服务器的 `pactl`；播放测试音还需要 `speaker-test`。机器人端 ALSA 设备识别直接读取 `/proc/asound/pcm`；切换默认音频设备和调节音量仍需要 PulseAudio/PipeWire 的 `pactl` 接口及相应用户权限。应用不会自动安装软件或执行 `sudo`。

## 目录

```text
src/                         React + TypeScript 界面
src-tauri/                   Tauri 2 Linux 外壳和 Rust SSH/设备后端
docs/product-spec.md          产品与安全规格
docs/first-direct-connection.md  无 Internet 直连操作手册
```

浏览器中的界面截图仅展示视觉设计，不表示真实设备状态：

![RoboLink 深色模式设计预览](./ui-preview.png)

![RoboLink 浅色模式设计预览](./ui-preview-light.png)
