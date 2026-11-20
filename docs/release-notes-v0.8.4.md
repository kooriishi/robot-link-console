# RoboLink v0.8.4 · Ubuntu 22.04

- 修复远程桌面以 root 运行仍报 `-auth guess` 找不到 X 授权的问题。`-auth guess` 只看 X 服务器命令行里的 `-auth` 参数，桌面会话的授权文件不在那里时就会失败。现在依次尝试：`-auth guess`、所有 X 服务器的 `-auth` 文件、开发板上同一显示（如 `:0`）的进程环境变量里的 `XAUTHORITY`、`/run/user/*/gdm/Xauthority`、lightdm 的授权文件、各用户的 `~/.Xauthority`，最后才是不带授权。
- 全部失败时，报错里会列出试过哪些授权文件，便于判断是显示编号不对还是桌面是 Wayland。
- 其他与 [v0.8.3](release-notes-v0.8.3.md) 相同。
