# RoboLink v0.2.2 候选版

**状态：待所有者审阅与批准。** 此版本基于本地 v0.2.1；尚未创建 GitHub Release、标签或上传安装包。

## 更新内容

新增独立 ALSA 硬件识别：连接机器人后读取 `/proc/asound/pcm`，列出播放和采集端点，不依赖 PipeWire 或 PulseAudio。ALSA 清单仅用于识别，不可用 `pactl` 控件切换或调节音量；原有 PulseAudio/PipeWire 操作保持不变。

页面首次访问后保留视图实例，避免反复挂载页面或重建终端。终端改用更紧凑的 Ubuntu Mono 系统字体栈，并将尺寸更新合并到动画帧，仅在列数或行数变化时调整 SSH PTY。

## Ubuntu 22.04 amd64 候选安装包

| 项目 | 详情 |
|---|---|
| 文件 | `RoboLink_0.2.2_ubuntu22.04_amd64.deb` |
| 大小 | 3,349,484 字节（约 3.19 MiB） |
| SHA-256 | `7698431c7a61efee86bebf8bec700b5752e6addecf4b12f626c1aa9b7a139fb6` |
| APT 依赖 | `libwebkit2gtk-4.1-0`、`libgtk-3-0` |
| 安装 | `sudo apt install ./RoboLink_0.2.2_ubuntu22.04_amd64.deb` |

## 验证

`npm run build`、`cargo fmt -- --check`、`cargo clippy --all-targets -- -D warnings` 均通过；Rust 单元测试 10 项全部通过，包含 ALSA 播放/采集与无效记录解析。`.deb` 在 Ubuntu 22.04 Jammy 用户空间内构建并通过 APT 安装测试；动态库均能解析，最高 GLIBC 符号版本为 2.34（Jammy 提供 glibc 2.35）。

本次没有连接实际机器人，因此未验证真实 ALSA 硬件枚举或物理音频播放。发布动作仍需所有者确认。