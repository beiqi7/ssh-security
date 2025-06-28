#!/bin/bash

# SSH 安全配置一键脚本
# 使用方法: sudo bash ssh_security.sh

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 日志函数
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# 检查是否为 root 用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "请使用 root 权限运行此脚本: sudo $0"
    fi
}

# 备份原始配置文件
backup_config() {
    local backup_dir="/root/ssh_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    if [[ -f /etc/ssh/sshd_config ]]; then
        cp /etc/ssh/sshd_config "$backup_dir/"
        log "SSH 配置文件已备份到: $backup_dir/sshd_config"
    fi
    
    echo "$backup_dir" > /tmp/ssh_backup_path
}

# 获取当前用户信息
get_user_info() {
    if [[ -n "$SUDO_USER" ]]; then
        CURRENT_USER="$SUDO_USER"
    else
        read -p "请输入要保留 SSH 访问权限的用户名: " CURRENT_USER
    fi
    
    if ! id "$CURRENT_USER" &>/dev/null; then
        error "用户 $CURRENT_USER 不存在"
    fi
    
    log "将为用户 $CURRENT_USER 保留 SSH 访问权限"
}

# 从 beiqi7 GitHub 获取公钥
get_beiqi7_keys() {
    local user_home=$(eval echo ~$CURRENT_USER)
    local ssh_dir="$user_home/.ssh"
    
    log "正在从 GitHub 获取 beiqi7 的公钥..."
    
    local github_keys_url="https://github.com/beiqi7.keys"
    local temp_keys="/tmp/github_keys_$"
    
    if curl -sf "$github_keys_url" -o "$temp_keys"; then
        if [[ -s "$temp_keys" ]]; then
            local key_count=$(wc -l < "$temp_keys")
            echo "找到 $key_count 个公钥:"
            echo "----------------------------------------"
            cat "$temp_keys" | nl -w2 -s') '
            echo "----------------------------------------"
            
            # 检测是否通过管道运行
            if [[ -t 0 ]]; then
                read -p "是否添加所有公钥? [Y/n]: " confirm
                confirm=${confirm:-Y}
            else
                confirm="Y"
                echo "检测到管道模式，自动确认添加公钥..."
            fi
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                cat "$temp_keys" >> "$ssh_dir/authorized_keys"
                chown "$CURRENT_USER:$CURRENT_USER" "$ssh_dir/authorized_keys"
                chmod 600 "$ssh_dir/authorized_keys"
                log "已成功添加 $key_count 个公钥"
            else
                error "操作已取消，无法继续配置 SSH 安全设置"
            fi
        else
            error "GitHub 用户 beiqi7 没有公开的 SSH 密钥，请先在 GitHub 中添加 SSH 密钥"
        fi
    else
        error "无法获取 GitHub 用户 beiqi7 的公钥，请检查网络连接"
    fi
    
    rm -f "$temp_keys"
}

# 配置密钥认证
setup_key_auth() {
    local user_home=$(eval echo ~$CURRENT_USER)
    local ssh_dir="$user_home/.ssh"
    
    # 创建 .ssh 目录
    if [[ ! -d "$ssh_dir" ]]; then
        mkdir -p "$ssh_dir"
        chown "$CURRENT_USER:$CURRENT_USER" "$ssh_dir"
        chmod 700 "$ssh_dir"
        log "已创建 .ssh 目录: $ssh_dir"
    fi
    
    # 检查是否已有密钥
    if [[ -f "$ssh_dir/authorized_keys" ]] && [[ -s "$ssh_dir/authorized_keys" ]]; then
        log "检测到已有 SSH 密钥配置"
        read -p "是否追加新的公钥? [Y/n]: " append_key
        append_key=${append_key:-Y}
        if [[ ! "$append_key" =~ ^[Yy]$ ]]; then
            log "保持现有密钥配置"
            return 0
        fi
    fi
    
    # 直接从 beiqi7 GitHub 获取公钥
    get_beiqi7_keys
}

# 生成 SSH 密钥对
generate_ssh_key() {
    local user_home=$(eval echo ~$CURRENT_USER)
    local ssh_dir="$user_home/.ssh"
    
    # 生成密钥对
    sudo -u "$CURRENT_USER" ssh-keygen -t rsa -b 4096 -f "$ssh_dir/id_rsa" -N "" -C "$CURRENT_USER@$(hostname)"
    
    # 设置 authorized_keys
    sudo -u "$CURRENT_USER" cp "$ssh_dir/id_rsa.pub" "$ssh_dir/authorized_keys"
    chmod 600 "$ssh_dir/authorized_keys"
    
    log "SSH 密钥对已生成"
    log "私钥位置: $ssh_dir/id_rsa"
    log "公钥位置: $ssh_dir/id_rsa.pub"
    
    echo
    warn "请立即下载私钥文件到本地，并妥善保管！"
    echo "私钥内容:"
    echo "----------------------------------------"
    cat "$ssh_dir/id_rsa"
    echo "----------------------------------------"
    echo
    read -p "请确认已保存私钥，按 Enter 继续..."
}

# 从 GitHub 获取公钥
get_github_key() {
    local user_home=$(eval echo ~$CURRENT_USER)
    local ssh_dir="$user_home/.ssh"
    
    echo "请选择公钥来源:"
    echo "1) 从 beiqi7 GitHub 用户获取 (推荐)"
    echo "2) 从 ssh-security 仓库获取"
    echo "3) 手动粘贴公钥"
    
    read -p "请选择 [1-3]: " key_source
    
    case $key_source in
        1)
            get_beiqi7_keys
            ;;
        2)
            get_repo_keys
            ;;
        3)
            add_manual_key
            ;;
        *)
            error "无效选择"
            ;;
    esac
}

# 从 GitHub 用户获取公钥
get_github_user_keys() {
    local user_home=$(eval echo ~$CURRENT_USER)
    local ssh_dir="$user_home/.ssh"
    
    read -p "请输入 GitHub 用户名: " github_user
    
    if [[ -z "$github_user" ]]; then
        error "GitHub 用户名不能为空"
    fi
    
    log "正在从 GitHub 获取用户 $github_user 的公钥..."
    
    local github_keys_url="https://github.com/$github_user.keys"
    local temp_keys="/tmp/github_keys_$"
    
    if curl -sf "$github_keys_url" -o "$temp_keys"; then
        if [[ -s "$temp_keys" ]]; then
            echo "找到以下公钥:"
            echo "----------------------------------------"
            cat "$temp_keys" | nl -w2 -s') '
            echo "----------------------------------------"
            
            read -p "是否添加所有公钥? [y/N]: " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                cat "$temp_keys" >> "$ssh_dir/authorized_keys"
                chown "$CURRENT_USER:$CURRENT_USER" "$ssh_dir/authorized_keys"
                chmod 600 "$ssh_dir/authorized_keys"
                log "已添加 $(wc -l < "$temp_keys") 个公钥"
            else
                warn "操作已取消"
            fi
        else
            error "用户 $github_user 没有公开的 SSH 密钥"
        fi
    else
        error "无法获取 GitHub 用户 $github_user 的公钥，请检查用户名或网络连接"
    fi
    
    rm -f "$temp_keys"
}

# 从 GitHub raw 文件获取公钥
get_github_raw_key() {
    local user_home=$(eval echo ~$CURRENT_USER)
    local ssh_dir="$user_home/.ssh"
    
    echo "请输入 GitHub raw 文件 URL (例如: https://raw.githubusercontent.com/username/repo/main/id_rsa.pub):"
    read -r github_url
    
    if [[ -z "$github_url" ]]; then
        error "URL 不能为空"
    fi
    
    log "正在从 GitHub 获取公钥文件..."
    
    local temp_key="/tmp/github_key_$"
    
    if curl -sf "$github_url" -o "$temp_key"; then
        if [[ -s "$temp_key" ]]; then
            echo "公钥内容:"
            echo "----------------------------------------"
            cat "$temp_key"
            echo "----------------------------------------"
            
            read -p "是否添加此公钥? [y/N]: " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                cat "$temp_key" >> "$ssh_dir/authorized_keys"
                chown "$CURRENT_USER:$CURRENT_USER" "$ssh_dir/authorized_keys"
                chmod 600 "$ssh_dir/authorized_keys"
                log "公钥已添加"
            else
                warn "操作已取消"
            fi
        else
            error "获取到的文件为空"
        fi
    else
        error "无法获取公钥文件，请检查 URL 或网络连接"
    fi
    
    rm -f "$temp_key"
}

# 手动添加公钥
add_manual_key() {
    local user_home=$(eval echo ~$CURRENT_USER)
    local ssh_dir="$user_home/.ssh"
    
    echo "请粘贴您的 SSH 公钥 (通常以 ssh-rsa 或 ssh-ed25519 开头):"
    read -r public_key
    
    if [[ -z "$public_key" ]]; then
        error "公钥不能为空"
    fi
    
    echo "$public_key" >> "$ssh_dir/authorized_keys"
    chown "$CURRENT_USER:$CURRENT_USER" "$ssh_dir/authorized_keys"
    chmod 600 "$ssh_dir/authorized_keys"
    
    log "SSH 公钥已添加"
}

# 配置 SSH 安全设置
configure_ssh() {
    local config_file="/etc/ssh/sshd_config"
    
    log "开始配置 SSH 安全设置..."
    
    # 读取自定义端口
    if [[ -t 0 ]]; then
        read -p "请输入新的 SSH 端口 (默认: 22): " new_port
    else
        echo "检测到管道模式，使用默认端口 22"
        new_port="22"
    fi
    new_port=${new_port:-22}
    
    # 验证端口范围
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [[ $new_port -lt 1 ]] || [[ $new_port -gt 65535 ]]; then
        error "无效的端口号: $new_port"
    fi
    
    # 创建新的配置文件
    cat > "$config_file" << EOF
# SSH 安全配置 - 由脚本自动生成于 $(date)

# 基础设置
Port $new_port
AddressFamily inet
ListenAddress 0.0.0.0

# 协议和加密
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# 认证设置
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# 用户和权限
PermitRootLogin no
AllowUsers $CURRENT_USER
MaxAuthTries 3
MaxSessions 2

# 连接设置
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60
MaxStartups 2:30:10

# 安全选项
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
PermitUserEnvironment no
StrictModes yes

# 日志
SyslogFacility AUTH
LogLevel INFO

# Banner
Banner /etc/ssh/banner
EOF

    log "SSH 配置已更新"
    log "新端口: $new_port"
    log "仅允许用户: $CURRENT_USER"
}

# 创建登录横幅
create_banner() {
    cat > /etc/ssh/banner << 'EOF'
================================================================================
                          WARNING - AUTHORIZED ACCESS ONLY
================================================================================
This system is for authorized users only. All activities are logged and
monitored. Unauthorized access is prohibited and will be prosecuted to the
full extent of the law.
================================================================================
EOF
    log "SSH 登录横幅已创建"
}

# 配置防火墙
configure_firewall() {
    local ssh_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')
    
    # 检查防火墙类型
    if command -v ufw &> /dev/null; then
        log "配置 UFW 防火墙..."
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow "$ssh_port"/tcp
        ufw --force enable
        log "UFW 防火墙已配置"
    elif command -v firewall-cmd &> /dev/null; then
        log "配置 firewalld 防火墙..."
        systemctl start firewalld
        systemctl enable firewalld
        firewall-cmd --permanent --remove-service=ssh
        firewall-cmd --permanent --add-port="$ssh_port"/tcp
        firewall-cmd --reload
        log "firewalld 防火墙已配置"
    else
        warn "未检测到支持的防火墙，请手动配置防火墙规则"
        warn "请确保允许端口 $ssh_port 的 TCP 连接"
    fi
}

# 测试 SSH 配置
test_ssh_config() {
    log "测试 SSH 配置..."
    
    if sshd -T &>/dev/null; then
        log "SSH 配置语法检查通过"
    else
        error "SSH 配置语法错误，请检查配置文件"
    fi
}

# 重启 SSH 服务
restart_ssh() {
    log "重启 SSH 服务..."
    
    if systemctl is-active --quiet sshd; then
        systemctl restart sshd
    elif systemctl is-active --quiet ssh; then
        systemctl restart ssh
    else
        error "无法确定 SSH 服务名称"
    fi
    
    if systemctl is-active --quiet sshd || systemctl is-active --quiet ssh; then
        log "SSH 服务重启成功"
    else
        error "SSH 服务重启失败"
    fi
}

# 显示配置摘要
show_summary() {
    local ssh_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')
    local backup_path=$(cat /tmp/ssh_backup_path 2>/dev/null || echo "未知")
    
    echo
    echo "========================================"
    echo "           SSH 配置完成摘要"
    echo "========================================"
    echo "SSH 端口: $ssh_port"
    echo "允许用户: $CURRENT_USER"
    echo "认证方式: 仅密钥认证 (从 GitHub beiqi7 获取)"
    echo "Root 登录: 已禁用"
    echo "配置备份: $backup_path"
    echo "========================================"
    echo
    warn "重要提醒:"
    echo "1. 请确保 Termius 中有对应的私钥"
    echo "2. 请使用新端口和密钥测试连接"
    echo "3. 确认连接正常后再断开当前会话"
    echo "4. 新的连接命令: ssh -p $ssh_port $CURRENT_USER@$(hostname -I | awk '{print $1}')"
    echo "5. 一键脚本地址: curl -sSL https://raw.githubusercontent.com/beiqi7/ssh-security/main/setup.sh | sudo bash"
    echo
}

# 主函数
main() {
    log "开始 SSH 安全配置..."
    
    check_root
    backup_config
    get_user_info
    setup_key_auth
    configure_ssh
    create_banner
    test_ssh_config
    configure_firewall
    restart_ssh
    show_summary
    
    log "SSH 安全配置完成！"
}

# 执行主函数
main "$@"
