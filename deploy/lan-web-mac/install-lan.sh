#!/bin/zsh
# MacCellular 局域网网页模式安装器（家庭 Mac）。
#
#   ./deploy/lan-web-mac/install-lan.sh check  [选项]   # 只检查，不改动系统
#   ./deploy/lan-web-mac/install-lan.sh apply  [选项]   # 安装并启动 LaunchAgent
#   ./deploy/lan-web-mac/install-lan.sh remove          # 停止并移除 LaunchAgent（保留数据）
#
# 选项：
#   --binary PATH          已构建的 arm64 后端，默认 dist/djonehub-macos-arm64
#   --lan-listen ADDR      局域网监听地址，默认 0.0.0.0:7579
#   --console-port PORT    本机管理页端口（仅 127.0.0.1），默认 7576
#   --password-file PATH   现有 mode-0600 密码文件；省略时首次安装会隐藏读取并写入 config/lan-web-password
#   --tls                  生成自签名证书并以 HTTPS 提供（手机安装 PWA/通知需要）
#   --no-control           只读模式：网页可查看但不能发送短信
#
# 不修改系统全局设置，不开放路由器端口；只在用户目录创建文件和一个 LaunchAgent。
set -euo pipefail

ROOT_DIR=${0:A:h:h:h}
MODE=${1:-}
[[ -n "$MODE" ]] && shift || true

RUNTIME_DIR="$HOME/Library/Application Support/MacCellular"
LOG_DIR="$HOME/Library/Logs/MacCellular"
LABEL="io.maccellular.lan-web"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
TEMPLATE="$ROOT_DIR/deploy/lan-web-mac/$LABEL.plist.example"

BINARY="$ROOT_DIR/dist/djonehub-macos-arm64"
LAN_LISTEN="0.0.0.0:7579"
CONSOLE_PORT="7576"
PASSWORD_SOURCE=""
TLS=0
CONTROL=1

die() { print -u2 -- "错误：$*"; exit 1; }
note() { print -- "$*"; }

while (( $# )); do
  case "$1" in
    --binary) BINARY=${2:?}; shift 2 ;;
    --lan-listen) LAN_LISTEN=${2:?}; shift 2 ;;
    --console-port) CONSOLE_PORT=${2:?}; shift 2 ;;
    --password-file) PASSWORD_SOURCE=${2:?}; shift 2 ;;
    --tls) TLS=1; shift ;;
    --no-control) CONTROL=0; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "未知参数 $1" ;;
  esac
done

case "$MODE" in
  check|apply|remove) ;;
  *) die "第一个参数必须是 check、apply 或 remove" ;;
esac

BIN_DIR="$RUNTIME_DIR/bin"
CONFIG_DIR="$RUNTIME_DIR/config"
TLS_DIR="$RUNTIME_DIR/config/lan-web-tls"
INSTALLED_BINARY="$BIN_DIR/djonehub-macos.lan-web"
PASSWORD_FILE="$CONFIG_DIR/lan-web-password"
LOG_FILE="$LOG_DIR/lan-web.log"

if [[ "$MODE" == remove ]]; then
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
  rm -f "$PLIST"
  note "已停止并移除 $LABEL。短信、录音、配置和密码文件均保留在：$RUNTIME_DIR"
  exit 0
fi

[[ "$(uname -m)" == arm64 ]] || die "当前只支持 Apple Silicon Mac"
[[ -x "$BINARY" ]] || die "未找到可执行后端 $BINARY，请先运行 ./scripts/build-macos.sh"
file "$BINARY" | grep -q arm64 || die "$BINARY 不是 arm64 二进制"
( "$BINARY" -h 2>&1 || true ) | grep -q -- '-lan-web-listen' || die "该二进制不支持 -lan-web-listen，请使用本仓库当前版本重新构建"
[[ "$LAN_LISTEN" == *:* ]] || die "--lan-listen 必须是 host:port"
[[ "$CONSOLE_PORT" == <1024-65535> ]] || die "--console-port 必须是 1024-65535 的端口"
[[ -f "$TEMPLATE" ]] || die "缺少模板 $TEMPLATE"

if [[ -n "$PASSWORD_SOURCE" ]]; then
  [[ -f "$PASSWORD_SOURCE" ]] || die "密码文件 $PASSWORD_SOURCE 不存在"
  [[ "$(stat -f '%Lp' "$PASSWORD_SOURCE")" == 600 ]] || die "密码文件必须是 mode 0600"
  (( $(wc -c < "$PASSWORD_SOURCE") >= 10 )) || die "密码至少 10 个字符"
elif [[ ! -f "$PASSWORD_FILE" ]]; then
  if [[ "$MODE" == check ]]; then
    note "提示：$PASSWORD_FILE 尚不存在，apply 时会提示输入访问密码（不回显，不进入命令行参数）。"
  fi
fi

note "CHECK: binary=$BINARY"
note "CHECK: lan-listen=$LAN_LISTEN console=127.0.0.1:$CONSOLE_PORT tls=$TLS control=$CONTROL"
note "CHECK: runtime=$RUNTIME_DIR"
if lsof -nP -iTCP:"${LAN_LISTEN##*:}" -sTCP:LISTEN 2>/dev/null | grep -qv "$INSTALLED_BINARY"; then
  if ! launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; then
    die "端口 ${LAN_LISTEN##*:} 已被其他进程占用：$(lsof -nP -iTCP:"${LAN_LISTEN##*:}" -sTCP:LISTEN | tail -n +2 | awk '{print $1" pid "$2}' | head -1)"
  fi
fi
if [[ "$MODE" == check ]]; then
  note "CHECK PASS: 可以把 check 改为 apply 进行安装。"
  exit 0
fi

umask 077
mkdir -p "$BIN_DIR" "$CONFIG_DIR" "$LOG_DIR" "$HOME/Library/LaunchAgents"
chmod 700 "$RUNTIME_DIR" "$BIN_DIR" "$CONFIG_DIR" 2>/dev/null || true

# 密码文件：优先复制用户给出的文件；否则首次安装时隐藏读取。
if [[ -n "$PASSWORD_SOURCE" && "${PASSWORD_SOURCE:A}" != "${PASSWORD_FILE:A}" ]]; then
  install -m 600 "$PASSWORD_SOURCE" "$PASSWORD_FILE"
elif [[ -n "$PASSWORD_SOURCE" ]]; then
  chmod 600 "$PASSWORD_FILE"
elif [[ ! -f "$PASSWORD_FILE" ]]; then
  while true; do
    read -rs "pw1?请设置局域网访问密码（至少 10 个字符）："; print
    read -rs "pw2?请再输入一次："; print
    if [[ "$pw1" != "$pw2" ]]; then note "两次输入不一致，请重试。"; continue; fi
    if (( ${#pw1} < 10 )); then note "密码太短。"; continue; fi
    if [[ "$pw1" != "${pw1// /}" && "$pw1" == " "* ]]; then note "密码首尾不能有空格。"; continue; fi
    break
  done
  print -r -- "$pw1" > "$PASSWORD_FILE"
  chmod 600 "$PASSWORD_FILE"
  unset pw1 pw2
fi

# 可选自签名证书：SAN 覆盖本机全部私网 IPv4 和 <主机名>.local。
TLS_ARGS=""
if (( TLS )); then
  mkdir -p "$TLS_DIR"; chmod 700 "$TLS_DIR"
  CERT="$TLS_DIR/lan-web.crt"; KEY="$TLS_DIR/lan-web.key"
  if [[ ! -f "$CERT" || ! -f "$KEY" ]]; then
    local_host="$(scutil --get LocalHostName 2>/dev/null | tr 'A-Z' 'a-z').local"
    san="DNS:localhost,DNS:$local_host,IP:127.0.0.1"
    for ip in $(ifconfig | awk '/inet / && $2 != "127.0.0.1" {print $2}'); do
      case "$ip" in
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) san="$san,IP:$ip" ;;
      esac
    done
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout "$KEY" -out "$CERT" -days 1095 -subj "/CN=MacCellular LAN ($local_host)" \
      -addext "subjectAltName=$san" -addext "basicConstraints=CA:FALSE" \
      -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1 || die "openssl 生成证书失败"
    chmod 600 "$KEY" "$CERT"
    note "已生成自签名证书：$CERT（SAN: $san）"
  fi
  TLS_ARGS="<string>-lan-web-tls-cert</string><string>$CERT</string><string>-lan-web-tls-key</string><string>$KEY</string>"
fi

# 原子安装二进制并保留上一版本，便于回滚。
if [[ -f "$INSTALLED_BINARY" ]]; then cp -f "$INSTALLED_BINARY" "$INSTALLED_BINARY.previous"; fi
install -m 700 "$BINARY" "$INSTALLED_BINARY.tmp"
mv -f "$INSTALLED_BINARY.tmp" "$INSTALLED_BINARY"
codesign --verify --strict "$INSTALLED_BINARY" 2>/dev/null || codesign --force --sign - "$INSTALLED_BINARY"

esc() { print -r -- "$1" | sed -e 's/[&|]/\\&/g'; }
CONTROL_ARG='<string>-lan-web-control</string>'
(( CONTROL )) || CONTROL_ARG=''
sed -e "s|__BINARY__|$(esc "$INSTALLED_BINARY")|" \
    -e "s|__CONSOLE_PORT__|$CONSOLE_PORT|" \
    -e "s|__LAN_LISTEN__|$(esc "$LAN_LISTEN")|" \
    -e "s|__PASSWORD_FILE__|$(esc "$PASSWORD_FILE")|" \
    -e "s|<string>-lan-web-control</string>|$CONTROL_ARG|" \
    -e "s|__TLS_ARGS__|$(esc "$TLS_ARGS")|" \
    -e "s|__RUNTIME_DIR__|$(esc "$RUNTIME_DIR")|" \
    -e "s|__LOG_FILE__|$(esc "$LOG_FILE")|" \
    "$TEMPLATE" > "$PLIST.tmp"
plutil -lint "$PLIST.tmp" >/dev/null || die "渲染的 LaunchAgent 无效"
mv -f "$PLIST.tmp" "$PLIST"

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
launchctl kickstart -k "gui/$(id -u)/$LABEL" 2>/dev/null || true

scheme=http; (( TLS )) && scheme=https
port=${LAN_LISTEN##*:}
for _ in {1..30}; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | grep -q .; then break; fi
  sleep 0.5
done
lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | grep -q . || {
  tail -n 20 "$LOG_FILE" 2>/dev/null >&2
  die "服务未在 $port 端口监听，请查看 $LOG_FILE"
}
http_status=$(curl -sk -o /dev/null -w '%{http_code}' "$scheme://127.0.0.1:$port/api/remote/v1/session" || true)
[[ "$http_status" == 401 ]] || die "未登录访问应返回 401，实际为 $http_status"

note ""
note "安装完成。手机或电脑连接同一 Wi-Fi 后打开："
for ip in $(ifconfig | awk '/inet / && $2 != "127.0.0.1" {print $2}'); do
  case "$ip" in 10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) note "  $scheme://$ip:$port/remote/" ;; esac
done
note "  $scheme://$(scutil --get LocalHostName 2>/dev/null | tr 'A-Z' 'a-z').local:$port/remote/"
note "本机管理页：http://127.0.0.1:$CONSOLE_PORT/"
note "日志：$LOG_FILE"
(( TLS )) && note "自签名证书首次在手机上需要信任：$TLS_DIR/lan-web.crt（AirDrop 到手机后在“设置 → 通用 → VPN 与设备管理”中安装并在“证书信任设置”中开启）。"

exit 0
