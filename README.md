# RoboLink · 机器人调试台

面向无头 Linux 机器人的本地调试控制台原型。它运行在 Linux 开发机上，目标是让开发者通过一根**直接连接机器人与开发机的网线（不经过中间设备）**，完成发现、SSH 调试、服务查看和外设管理。

## 当前状态：可运行的 UI 原型

当前版本用于验证产品信息架构与主要交互。页面中的机器人、服务、网络、蓝牙和音频数据都是演示数据。按钮只产生本地界面反馈；终端只模拟少量输出，不会执行命令。它**不会连接你的机器人，也不会扫描或修改电脑/机器人网络**。

真实 SSH、网卡发现与配置、systemd、Wi-Fi、BlueZ 和音频操作将按 `docs/product-spec.md` 中的安全边界逐步实现。特别是有线网络按开发机 ↔ 机器人直接点对点连接设计，不假设存在路由器/交换机。

## Linux 开发运行

需要 Node.js 20+ 和 npm：

```bash
npm install
npm run dev
```

本地打开 Vite 输出的地址（默认 `http://localhost:5173`）。生产构建检查：

```bash
npm run build
npm run preview
```

## 项目结构

```text
src/                 React UI 原型
  App.tsx             页面与演示交互
  styles.css          桌面/移动端样式
docs/product-spec.md  产品、交互、安全和迭代规格
```

## 开发路线

1. Tauri 2 Linux 桌面外壳 + OpenSSH 连接与主机指纹校验。
2. 只读诊断与 systemd 服务操作。
3. 选定直连接口上的设备发现，以及显式确认、可回滚的地址配置。
4. 机器人 Wi-Fi、蓝牙、麦克风/扬声器控制和真实设备测试。

安全和首版范围详见 [`docs/product-spec.md`](docs/product-spec.md)。

## 界面预览

![RoboLink 设备总览界面](./ui-preview.png)
