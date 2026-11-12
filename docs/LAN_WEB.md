# 局域网网页访问（无需 Cloudflare / Tailscale）

`lan-web` 是一条独立的网页入口：家里的手机、平板或电脑连接同一 Wi-Fi 后，用浏览器
直接打开 Mac 的局域网地址，输入一次访问密码，就能使用手机端 PWA 查看和发送短信。
它不需要域名、Cloudflare 账户、Tunnel 或 Tailscale，也不会开放任何路由器端口。

| 项目 | 说明 |
| --- | --- |
| 监听 | 默认 `0.0.0.0:7579`（可用 `-lan-web-listen` 指定具体网卡 IP） |
| 认证 | 一个本机 mode-0600 文件中的访问密码；登录后使用 HttpOnly 会话 Cookie，30 天有效，重启服务不丢失 |
| 能力 | 状态、短信同步、短信发送与刷新（`-lan-web-control`）；不包含拨号、媒体、USB、AT、管理接口 |
| 防护 | 只接受私网 IP、`localhost`、`*.local` 等主机名（抵御 DNS rebinding）；同源 + CSRF 校验；每个客户端 15 分钟内 5 次失败即锁定，全局 30 次 |
| HTTPS | 可选 `-lan-web-tls-cert/-key`；手机“添加到主屏幕”的离线壳和通知需要 HTTPS |

## 安装

```sh
./scripts/build-macos.sh
./deploy/lan-web-mac/install-lan.sh check
./deploy/lan-web-mac/install-lan.sh apply
```

`apply` 会：

1. 把后端复制到 `~/Library/Application Support/MacCellular/bin/djonehub-macos.lan-web`（保留上一版本 `.previous`）；
2. 首次安装时隐藏读取访问密码并写入 `config/lan-web-password`（0600），也可用 `--password-file` 指定现有文件；
3. 渲染并加载 LaunchAgent `io.maccellular.lan-web`（`caffeinate -s` 包裹，接电时阻止睡眠）；
4. 确认 7579 已监听且未登录访问返回 401，然后打印手机可打开的地址。

常用选项：`--lan-listen 192.168.1.10:7579`、`--console-port 7576`、`--no-control`（只读）、`--tls`
（生成含本机私网 IP 与 `<主机名>.local` 的自签名证书）。`remove` 子命令停止并移除 LaunchAgent，
短信、录音、配置和密码文件全部保留。

同一台 Mac 上只运行一个后端进程；如果之前用 DMG 安装了 `io.maccellular.backend`，先卸载它，
否则两者会争抢 USB 模块。

## 手机端

1. 打开安装器打印的地址，例如 `http://192.168.3.200:7579/remote/`；
2. 输入访问密码；
3. iPhone 选择“分享 → 添加到主屏幕”，Android Chrome 选择“添加到主屏幕”。

纯 HTTP 下浏览器不会注册 Service Worker，页面仍可正常使用，只是没有离线壳。需要离线壳或
来电提醒时用 `--tls` 重新 `apply`，并把 `config/lan-web-tls/lan-web.crt` 安装到手机并开启信任。

## 手动运行（开发）

```sh
./dist/djonehub-macos-arm64 -demo -listen 127.0.0.1:7576 -web-console \
  -lan-web-listen 0.0.0.0:7579 -lan-web-password-file /绝对路径/lan-web-password -lan-web-control
```

## 安全边界

- 密码只以 SHA-256 形式驻留内存；会话文件 `lan-web/sessions.json` 只保存令牌哈希；
- 公网主机名（即使解析到局域网 IP）一律 403；
- 登录失败日志只记录客户端 IP，不记录密码；
- 局域网内的其他设备仍可能嗅探纯 HTTP 流量，家庭 Wi-Fi 应启用 WPA2/WPA3；对外网访问请继续使用
  Cloudflare Access 路径（[GETTING_STARTED.md](GETTING_STARTED.md)）。
