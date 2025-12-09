#!/bin/bash

# Sing-box Shadowsocks 一键安装脚本 (Debian 12)
# 支持 TCP/UDP/QUIC，内置随机 DoH 解析

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 配置参数
SING_BOX_VERSION="1.10.7"

# === 用户自定义配置修改开始 ===
# 随机选择 7005 - 7999 之间的端口
MIN_PORT=7005
MAX_PORT=7999
SS_PORT=$((RANDOM % (MAX_PORT - MIN_PORT + 1) + MIN_PORT))

# 节点密码固定为 AAABBBCCC
SS_PASSWORD="AAABBBCCC"
# === 用户自定义配置修改结束 ===

CIPHER="aes-128-gcm"

# DoH 服务器列表 (来自 doh.sh)
DOH_SERVERS=(
    "https://185.222.222.222/dns-query"
    "https://94.140.14.15/dns-query"
    "https://doh.pub/dns-query"
    "https://freedns.controld.com/p3"
    "https://helios.plan9-dns.com/dns-query"
    "https://dns11.quad9.net:443/dns-query"
    "https://wikimedia-dns.org/dns-query"
    "https://adblock.dns.mullvad.net/dns-query"
    "https://dns.brahma.world/dns-query"
    "https://doh.tiarap.org/dns-query"
    "https://77.88.8.2/dns-query"
    "https://sky.rethinkdns.com/dns-query"
    "https://jp.tiar.app/dns-query"
    "https://dns.njal.la/dns-query"
    "https://public.dns.iij.jp/dns-query"
    "https://dns0.eu/dns-query"
    "https://130.59.31.248/dns-query"
    "https://per.adfilter.net/dns-query"
    "https://dns.bebasid.com/unfiltered"
    "https://family.dns.mullvad.net/dns-query"
    "https://dns1.dnscrypt.ca/dns-query"
    "https://doh.opendns.com/dns-query"
    "https://doh.libredns.gr/ads"
    "https://pluton.plan9-dns.com/dns-query"
    "https://anycast.dns.nextdns.io/dns-query"
    "https://dns.twnic.tw/dns-query"
    "https://doh.cleanbrowsing.org/doh/adult-filter/"
    "https://1.1.1.1/dns-query"
    "https://dns.google/dns-query"
    "https://dns.quad9.net/dns-query"
    "https://dns.adguard-dns.com/dns-query"
)

# 随机选择主 DoH 和备用 DoH
RANDOM_INDEX=$((RANDOM % ${#DOH_SERVERS[@]}))
PRIMARY_DOH="${DOH_SERVERS[$RANDOM_INDEX]}"

# 选择3个不同的备用 DoH
BACKUP_DOH=()
for i in {1..3}; do
    while true; do
        BACKUP_INDEX=$((RANDOM % ${#DOH_SERVERS[@]}))
        BACKUP_CANDIDATE="${DOH_SERVERS[$BACKUP_INDEX]}"
        # 确保不与主 DoH 和已选备用重复
        if [[ "$BACKUP_CANDIDATE" != "$PRIMARY_DOH" ]] && [[ ! " ${BACKUP_DOH[@]} " =~ " ${BACKUP_CANDIDATE} " ]]; then
            BACKUP_DOH+=("$BACKUP_CANDIDATE")
            break
        fi
    done
done

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Sing-box Shadowsocks 服务器安装${NC}"
echo -e "${GREEN}  (随机 DoH 解析版本)${NC}"
echo -e "${GREEN}========================================${NC}"

# 检查 root 权限
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}错误: 请使用 root 权限运行此脚本${NC}"
   exit 1
fi

# 更新系统
echo -e "${YELLOW}[1/7] 更新系统软件包...${NC}"
apt update && apt upgrade -y
apt install -y curl wget tar gzip ufw

# 下载并安装 Sing-box
echo -e "${YELLOW}[2/7] 下载 Sing-box ${SING_BOX_VERSION}...${NC}"
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        DOWNLOAD_ARCH="amd64"
        ;;
    aarch64)
        DOWNLOAD_ARCH="arm64"
        ;;
    *)
        echo -e "${RED}不支持的架构: $ARCH${NC}"
        exit 1
        ;;
esac

DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${DOWNLOAD_ARCH}.tar.gz"

cd /tmp
wget -O sing-box.tar.gz "$DOWNLOAD_URL"
tar -xzf sing-box.tar.gz
mv sing-box-${SING_BOX_VERSION}-linux-${DOWNLOAD_ARCH}/sing-box /usr/local/bin/
chmod +x /usr/local/bin/sing-box
rm -rf sing-box.tar.gz sing-box-${SING_BOX_VERSION}-linux-${DOWNLOAD_ARCH}

# 创建配置目录
echo -e "${YELLOW}[3/7] 创建配置文件 (随机 DoH)...${NC}"
mkdir -p /etc/sing-box

# 生成 Sing-box 配置 (内置随机 DNS over HTTPS)
cat > /etc/sing-box/config.json <<'EOF'
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "primary",
        "address": "PRIMARY_DOH_PLACEHOLDER",
        "address_resolver": "local"
      },
      {
        "tag": "backup1",
        "address": "BACKUP1_DOH_PLACEHOLDER",
        "address_resolver": "local"
      },
      {
        "tag": "backup2",
        "address": "BACKUP2_DOH_PLACEHOLDER",
        "address_resolver": "local"
      },
      {
        "tag": "backup3",
        "address": "BACKUP3_DOH_PLACEHOLDER",
        "address_resolver": "local"
      },
      {
        "tag": "local",
        "address": "local",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "outbound": "any",
        "server": "primary"
      }
    ],
    "strategy": "prefer_ipv4",
    "disable_cache": false,
    "disable_expire": false,
    "final": "primary"
  },
  "inbounds": [
    {
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "::",
      "listen_port": SS_PORT_PLACEHOLDER,
      "tcp_fast_open": true,
      "tcp_multi_path": false,
      "udp_fragment": true,
      "sniff": true,
      "sniff_override_destination": true,
      "method": "CIPHER_PLACEHOLDER",
      "password": "PASSWORD_PLACEHOLDER"
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "rules": [
      {
        "ip_is_private": true,
        "outbound": "block"
      }
    ],
    "final": "direct",
    "auto_detect_interface": true
  }
}
EOF

# 替换占位符
sed -i "s|PRIMARY_DOH_PLACEHOLDER|${PRIMARY_DOH}|g" /etc/sing-box/config.json
sed -i "s|BACKUP1_DOH_PLACEHOLDER|${BACKUP_DOH[0]}|g" /etc/sing-box/config.json
sed -i "s|BACKUP2_DOH_PLACEHOLDER|${BACKUP_DOH[1]}|g" /etc/sing-box/config.json
sed -i "s|BACKUP3_DOH_PLACEHOLDER|${BACKUP_DOH[2]}|g" /etc/sing-box/config.json
sed -i "s|SS_PORT_PLACEHOLDER|${SS_PORT}|g" /etc/sing-box/config.json
sed -i "s|CIPHER_PLACEHOLDER|${CIPHER}|g" /etc/sing-box/config.json
sed -i "s|PASSWORD_PLACEHOLDER|${SS_PASSWORD}|g" /etc/sing-box/config.json

# 验证配置文件
echo -e "${YELLOW}[3.5/7] 验证配置文件...${NC}"
if ! /usr/local/bin/sing-box check -c /etc/sing-box/config.json; then
    echo -e "${RED}配置文件验证失败！${NC}"
    cat /etc/sing-box/config.json
    exit 1
fi

# 创建 systemd 服务
echo -e "${YELLOW}[4/7] 创建 systemd 服务...${NC}"
cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

# 配置防火墙
echo -e "${YELLOW}[5/7] 配置防火墙规则...${NC}"
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow ${SS_PORT}/tcp
ufw allow ${SS_PORT}/udp

# 启用 IP 转发和优化内核参数
echo -e "${YELLOW}[6/7] 优化系统参数...${NC}"
cat >> /etc/sysctl.conf <<EOF

# Sing-box 优化参数
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.tcp_fastopen = 3
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = cubic
net.ipv4.tcp_rmem = 4096 87380 4194304
net.ipv4.tcp_wmem = 4096 16384 4194304
net.core.rmem_max = 4194304
net.core.wmem_max = 4194304
net.ipv4.tcp_mtu_probing = 1
fs.file-max = 1048576
net.core.somaxconn = 1024
net.ipv4.tcp_max_syn_backlog = 2048
EOF

sysctl -p

# 启动服务
echo -e "${YELLOW}[7/7] 启动 Sing-box 服务...${NC}"
systemctl daemon-reload
systemctl enable sing-box
systemctl start sing-box

# 等待服务启动
sleep 2

# 检查服务状态
if systemctl is-active --quiet sing-box; then
    echo -e "${GREEN}✓ Sing-box 服务启动成功${NC}"
else
    echo -e "${RED}✗ Sing-box 服务启动失败，查看日志：${NC}"
    journalctl -u sing-box -n 20 --no-pager
    exit 1
fi

# 获取服务器 IP
SERVER_IP=$(curl -s -4 ifconfig.me || curl -s -4 icanhazip.com)

# 显示配置信息
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  安装完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}服务器信息:${NC}"
echo -e "  服务器地址: ${GREEN}${SERVER_IP}${NC}"
echo -e "  端口: ${GREEN}${SS_PORT}${NC} (随机于 7005-7999)"
echo -e "  密码: ${GREEN}${SS_PASSWORD}${NC}"
echo -e "  加密方式: ${GREEN}${CIPHER}${NC}"
echo ""
echo -e "${YELLOW}连接 URI:${NC}"
echo -e "  ${GREEN}ss://${CIPHER}:${SS_PASSWORD}@${SERVER_IP}:${SS_PORT}${NC}"
echo ""
echo -e "${YELLOW}DNS 配置说明:${NC}"
echo -e "  ${GREEN}✓ 服务器已内置随机 DoH 解析功能${NC}"
echo -e "  ${GREEN}✓ 主 DNS: ${PRIMARY_DOH}${NC}"
echo -e "  ${GREEN}✓ 备用 DNS 1: ${BACKUP_DOH[0]}${NC}"
echo -e "  ${GREEN}✓ 备用 DNS 2: ${BACKUP_DOH[1]}${NC}"
echo -e "  ${GREEN}✓ 备用 DNS 3: ${BACKUP_DOH[2]}${NC}"
echo -e "  ${GREEN}✓ 所有 DNS 查询自动通过 HTTPS 加密${NC}"
echo -e "  ${GREEN}✓ 无需客户端额外配置 DNS${NC}"
echo ""
echo -e "${YELLOW}管理命令:${NC}"
echo -e "  查看状态: ${GREEN}systemctl status sing-box${NC}"
echo -e "  启动服务: ${GREEN}systemctl start sing-box${NC}"
echo -e "  停止服务: ${GREEN}systemctl stop sing-box${NC}"
echo -e "  重启服务: ${GREEN}systemctl restart sing-box${NC}"
echo -e "  查看日志: ${GREEN}journalctl -u sing-box -f${NC}"
echo ""
echo -e "${YELLOW}配置文件位置:${NC}"
echo -e "  ${GREEN}/etc/sing-box/config.json${NC}"
echo ""
echo -e "${GREEN}========================================${NC}"

# 保存配置到文件
cat > /root/ss-config.txt <<EOF
Shadowsocks 服务器配置信息 (随机 DoH)
========================================
服务器地址: ${SERVER_IP}
端口: ${SS_PORT} (随机于 7005-7999)
密码: ${SS_PASSWORD}
加密方式: ${CIPHER}

连接 URI:
ss://${CIPHER}:${SS_PASSWORD}@${SERVER_IP}:${SS_PORT}

配置文件: /etc/sing-box/config.json

DNS 隐私说明:
- 服务器端已内置随机 DoH 解析
- 主 DNS: ${PRIMARY_DOH}
- 备用 DNS 1: ${BACKUP_DOH[0]}
- 备用 DNS 2: ${BACKUP_DOH[1]}
- 备用 DNS 3: ${BACKUP_DOH[2]}
- 所有 DNS 查询通过 HTTPS 加密
- 客户端无需额外配置 DNS

可用 DoH 服务器总数: ${#DOH_SERVERS[@]}
========================================
EOF

echo -e "${GREEN}配置信息已保存到: /root/ss-config.txt${NC}"
