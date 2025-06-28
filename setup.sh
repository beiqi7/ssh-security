#!/bin/bash

# SSH 安全配置一键脚本 - 改进版
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
    
    # 备份当前的防火墙规则
    if command -v ufw &> /dev/null; then
        ufw status numbered > "$backup_dir/ufw_rules.txt" 2>/dev/null || true
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
    local temp_keys="/tmp/github_keys_$$"
    
    # 添加重试机制
    local retry_count=3
    local retry_delay=2
    
    for i in $(seq 1 $retry_count); do
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
                    # 创建临时文件并设置权限
                    local temp_auth="/tmp/authorized_keys_$$"
                    touch "$temp_auth"
                    chmod 600 "$temp_auth"
                    
                    # 如果已有authorized_keys，先复制
                    if [[ -f "$ssh_dir/authorized_keys" ]]; then
                        cat "$ssh_dir/authorized_keys" > "$temp_auth"
                    fi
                    
                    # 添加新密钥
                    cat "$temp_keys" >> "$temp_auth"
                    
                    # 原子性移动文件
                    mv "$temp_auth" "$ssh_dir/authorized_keys"
                    chown "$CURRENT_USER:$CURRENT_USER" "$ssh_dir/authorized_keys"
                    
                    log "已成功添加 $key_count 个公钥"
                    rm -f "$temp_keys"
                    return 0
                else
                    error "操作已取消，无法继续配置 SSH 安全设置"
                fi
            else
                warn "GitHub 用户 beiqi7 没有公开的 SSH 密钥"
            fi
        else
            warn "第 $i 次尝试失败，等待 $retry_delay 秒后重试..."
            sleep $retry_delay
        fi
    done
    
    rm -f "$temp_keys"
    error "无法获取 GitHub 用户 beiqi7 的公钥，请检查网络连接"
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
        if [[ -t 0 ]]; then
            read -p "是否追加新的公钥? [Y/n]: " append_key
            append_key=${append_key:-Y}
            if [[ ! "$append_key" =~ ^[Yy]$ ]]; then
                log "保持现有密钥配置"
                return 0
            fi
        fi
    fi
    
    # 直接从 beiqi7 GitHub 获取公钥
    get_beiqi7_keys
}

# 更新SSH配置（不覆盖整个文件）
update_ssh_config() {
    local config_file="/etc/ssh/sshd_config"
    local temp_config="/tmp/sshd_config_$$"
    local new_port="$1"
    
    # 复制原配置
    cp "$config_file" "$temp_config"
    
    # 定义要更新的配置项
    declare -A configs=(
        ["Port"]="$new_port"
        ["Protocol"]="2"
        ["PubkeyAuthentication"]="yes"
        ["PasswordAuthentication"]="no"
        ["PermitEmptyPasswords"]="no"
        ["ChallengeResponseAuthentication"]="no"
        ["PermitRootLogin"]="no"
        ["AllowUsers"]="$CURRENT_USER"
        ["MaxAuthTries"]="3"
        ["MaxSessions"]="2"
        ["ClientAliveInterval"]="300"
        ["ClientAliveCountMax"]="2"
        ["LoginGraceTime"]="60"
        ["X11Forwarding"]="no"
        ["StrictModes"]="yes"
        ["UsePAM"]="yes"
    )
    
    # 更新配置项
    for key in "${!configs[@]}"; do
        if grep -q "^#*${key}\s" "$temp_config"; then
            sed -i "s/^#*${key}\s.*/${key} ${configs[$key]}/" "$temp_config"
        else
            echo "${key} ${configs[$key]}" >> "$temp_config"
        fi
    done
    
    # 验证配置
    if sshd -t -f "$temp_config" &>/dev/null; then
        mv "$temp_config" "$config_file"
        log "SSH 配置已更新"
    else
        rm -f "$temp_config"
        error "SSH 配置验证失败"
    fi
}

# 配置 SSH 安全设置
configure_ssh() {
    log "开始配置 SSH 安全设置..."
    
    # 读取自定义端口
    if [[ -t 0 ]]; then
        read -p "请输入新的 SSH 端口 (默认: 22): " new_port
    else
        echo "检测到管道模式，使用默认端口 22"
        new_port="22"
    fi
    new_port=${new_port:-22}
    
    # 验证端口范围（修正数值比较）
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || (( new_port < 1 )) || (( new_port > 65535 )); then
        error "无效的端口号: $new_port"
    fi
    
    # 更新配置而不是覆盖
    update_ssh_config "$new_port"
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
    
    # 确保banner配置已启用
    if ! grep -q "^Banner\s*/etc/ssh/banner" /etc/ssh/sshd_config; then
        echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config
    fi
    
    log "SSH 登录横幅已创建"
}

# 配置防火墙（更安全的方式）
configure_firewall() {
    local ssh_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')
    
    # 检查防火墙类型
    if command -v ufw &> /dev/null; then
        log "配置 UFW 防火墙..."
        
        # 先添加新规则，再删除旧规则
        ufw allow "$ssh_port"/tcp
        
        # 如果端口改变了，删除默认的22端口
        if [[ "$ssh_port" != "22" ]]; then
            ufw delete allow 22/tcp 2>/dev/null || true
        fi
        
        ufw --force enable
        log "UFW 防火墙已配置"
        
    elif command -v firewall-cmd &> /dev/null; then
        log "配置 firewalld 防火墙..."
        systemctl start firewalld
        systemctl enable firewalld
        
        # 添加新端口
        firewall-cmd --permanent --add-port="$ssh_port"/tcp
        
        # 如果端口改变了，移除ssh服务
        if [[ "$ssh_port" != "22" ]]; then
            firewall-cmd --permanent --remove-service=ssh
        fi
        
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
        return 0
    else
        error "SSH 配置语法错误，请检查配置文件"
        return 1
    fi
}

# 重启 SSH 服务（带回滚）
restart_ssh() {
    log "重启 SSH 服务..."
    
    local service_name=""
    if systemctl is-active --quiet sshd; then
        service_name="sshd"
    elif systemctl is-active --quiet ssh; then
        service_name="ssh"
    else
        error "无法确定 SSH 服务名称"
    fi
    
    # 保存当前状态
    local backup_path=$(cat /tmp/ssh_backup_path)
    
    # 尝试重启
    if systemctl restart "$service_name"; then
        sleep 2
        if systemctl is-active --quiet "$service_name"; then
            log "SSH 服务重启成功"
            return 0
        fi
    fi
    
    # 重启失败，尝试恢复
    warn "SSH 服务重启失败，尝试恢复原配置..."
    if [[ -f "$backup_path/sshd_config" ]]; then
        cp "$backup_path/sshd_config" /etc/ssh/sshd_config
        systemctl restart "$service_name"
        error "SSH 服务重启失败，已恢复原配置"
    else
        error "SSH 服务重启失败，且无法恢复原配置"
    fi
}

# 显示配置摘要
show_summary() {
    local ssh_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')
    local backup_path=$(cat /tmp/ssh_backup_path 2>/dev/null || echo "未知")
    local server_ip=$(hostname -I | awk '{print $1}')
    
    echo
    echo "========================================"
    echo "           SSH 配置完成摘要"
    echo "========================================"
    echo "SSH 端口: $ssh_port"
    echo "允许用户: $CURRENT_USER"
    echo "认证方式: 仅密钥认证 (从 GitHub beiqi7 获取)"
    echo "Root 登录: 已禁用"
    echo "配置备份: $backup_path"
    echo "服务器 IP: $server_ip"
    echo "========================================"
    echo
    warn "重要提醒:"
    echo "1. 请确保已保存相应的私钥"
    echo "2. 建议先测试新配置，不要立即关闭当前会话"
    echo "3. 测试连接命令: ssh -p $ssh_port $CURRENT_USER@$server_ip"
    echo "4. 如遇问题，可从备份恢复: $backup_path/sshd_config"
    echo "5. 一键脚本地址: curl -sSL https://raw.githubusercontent.com/beiqi7/ssh-security/main/setup.sh | sudo bash"
    echo
    
    # 清理临时文件
    rm -f /tmp/ssh_backup_path
}

# 主函数
main() {
    log "开始 SSH 安全配置..."
    
    # 设置陷阱，确保清理临时文件
    trap 'rm -f /tmp/*_$$' EXIT
    
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
