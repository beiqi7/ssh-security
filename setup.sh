#!/bin/bash

# SSH 安全配置一键脚本 - 改进版
# 使用方法: sudo bash ssh_security.sh
# 应急恢复: sudo bash ssh_security.sh --recover

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

# 应急恢复功能
emergency_recover() {
    log "启动应急恢复模式..."
    
    # 查找最新的备份
    local backup_dir=$(find /root -name "ssh_backup_*" -type d 2>/dev/null | sort -r | head -1)
    
    if [[ -n "$backup_dir" && -f "$backup_dir/sshd_config" ]]; then
        log "找到备份配置: $backup_dir/sshd_config"
        cp "$backup_dir/sshd_config" /etc/ssh/sshd_config
        log "SSH配置文件已恢复"
    else
        warn "未找到备份配置，创建允许密码认证的临时配置..."
        
        # 临时启用密码认证
        sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
        sed -i 's/^PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null || true
        
        # 如果还有AllowUsers限制，注释掉
        sed -i 's/^AllowUsers/#AllowUsers/' /etc/ssh/sshd_config 2>/dev/null || true
    fi
    
    # 重启SSH服务
    if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
        log "SSH服务重启成功"
        log "应急恢复完成！现在应该可以使用密码登录了。"
    else
        error "SSH服务重启失败"
    fi
    
    exit 0
}

# 检查是否为应急恢复模式
if [[ "$1" == "--recover" ]]; then
    emergency_recover
fi

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
        # 检测是否通过管道运行
        if [[ -t 0 ]]; then
            read -p "请输入要保留 SSH 访问权限的用户名: " CURRENT_USER
        else
            # 管道模式下，尝试自动确定用户
            if [[ "$USER" != "root" ]]; then
                CURRENT_USER="$USER"
                echo "检测到管道模式，自动选择用户: $CURRENT_USER"
            else
                # 如果是root用户，尝试找到第一个普通用户
                CURRENT_USER=$(getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $1; exit}')
                if [[ -n "$CURRENT_USER" ]]; then
                    echo "检测到管道模式，自动选择用户: $CURRENT_USER"
                else
                    # 如果找不到普通用户，使用root
                    CURRENT_USER="root"
                    echo "检测到管道模式，使用root用户"
                fi
            fi
        fi
    fi
    
    if ! id "$CURRENT_USER" &>/dev/null; then
        error "用户 $CURRENT_USER 不存在"
    fi
    
    log "将为用户 $CURRENT_USER 保留 SSH 访问权限"
}

# 配置密钥认证
setup_key_auth() {
    # 为选定用户配置密钥
    setup_user_keys "$CURRENT_USER"
    
    # 如果选定用户不是root，也为root配置密钥
    if [[ "$CURRENT_USER" != "root" ]]; then
        log "同时为root用户配置SSH密钥..."
        setup_user_keys "root"
    fi
}

# 为指定用户设置SSH密钥
setup_user_keys() {
    local user="$1"
    local user_home=$(eval echo ~$user)
    local ssh_dir="$user_home/.ssh"
    
    log "为用户 $user 配置SSH密钥..."
    
    # 创建 .ssh 目录
    if [[ ! -d "$ssh_dir" ]]; then
        mkdir -p "$ssh_dir"
        chown "$user:$user" "$ssh_dir"
        chmod 700 "$ssh_dir"
        log "已创建 .ssh 目录: $ssh_dir"
    fi
    
    # 检查是否已有密钥
    if [[ -f "$ssh_dir/authorized_keys" ]] && [[ -s "$ssh_dir/authorized_keys" ]]; then
        log "检测到用户 $user 已有 SSH 密钥配置"
        if [[ -t 0 ]]; then
            read -p "是否为用户 $user 追加新的公钥? [Y/n]: " append_key
            append_key=${append_key:-Y}
            if [[ ! "$append_key" =~ ^[Yy]$ ]]; then
                log "保持用户 $user 现有密钥配置"
                return 0
            fi
        else
            echo "检测到管道模式，自动为用户 $user 确认追加公钥..."
            append_key="Y"
        fi
    fi
    
    # 从 beiqi7 GitHub 获取公钥
    get_beiqi7_keys_for_user "$user"
}

# 从 beiqi7 GitHub 为指定用户获取公钥
get_beiqi7_keys_for_user() {
    local user="$1"
    local user_home=$(eval echo ~$user)
    local ssh_dir="$user_home/.ssh"
    
    log "正在为用户 $user 从 GitHub 获取 beiqi7 的公钥..."
    
    local github_keys_url="https://github.com/beiqi7.keys"
    local temp_keys="/tmp/github_keys_${user}_$$"
    
    # 添加重试机制
    local retry_count=3
    local retry_delay=2
    
    for i in $(seq 1 $retry_count); do
        if curl -sf "$github_keys_url" -o "$temp_keys"; then
            if [[ -s "$temp_keys" ]]; then
                local key_count=$(wc -l < "$temp_keys")
                echo "为用户 $user 找到 $key_count 个公钥"
                
                # 创建临时文件并设置权限
                local temp_auth="/tmp/authorized_keys_${user}_$$"
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
                chown "$user:$user" "$ssh_dir/authorized_keys"
                
                log "已成功为用户 $user 添加 $key_count 个公钥"
                rm -f "$temp_keys"
                return 0
            else
                warn "GitHub 用户 beiqi7 没有公开的 SSH 密钥"
                rm -f "$temp_keys"
                return 1
            fi
        else
            warn "第 $i 次尝试失败，等待 $retry_delay 秒后重试..."
            sleep $retry_delay
        fi
    done
    
    rm -f "$temp_keys"
    error "无法获取 GitHub 用户 beiqi7 的公钥，请检查网络连接"
}

# 更新SSH配置（不覆盖整个文件）
update_ssh_config() {
    local config_file="/etc/ssh/sshd_config"
    local temp_config="/tmp/sshd_config_$$"
    local new_port="$1"
    
    # 复制原配置
    cp "$config_file" "$temp_config"
    
    # 构建AllowUsers列表，避免重复
    local allow_users="root"
    if [[ "$CURRENT_USER" != "root" ]]; then
        allow_users="root $CURRENT_USER"
    fi
    
    # 定义要更新的配置项（严格安全配置）
    declare -A configs=(
        ["Port"]="$new_port"
        ["Protocol"]="2"
        ["PubkeyAuthentication"]="yes"
        ["PasswordAuthentication"]="no"  # 关闭密码认证
        ["PermitEmptyPasswords"]="no"
        ["ChallengeResponseAuthentication"]="no"
        ["PermitRootLogin"]="yes"  # 允许root登录（使用公钥）
        ["AllowUsers"]="$allow_users"  # 智能构建用户列表
        ["MaxAuthTries"]="3"
        ["MaxSessions"]="5"
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
    local password_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')
    local root_login=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
    local allowed_users=$(grep "^AllowUsers" /etc/ssh/sshd_config | cut -d' ' -f2-)
    
    echo
    echo "========================================"
    echo "           SSH 配置完成摘要"
    echo "========================================"
    echo "SSH 端口: $ssh_port"
    echo "已配置用户: $allowed_users"
    echo "密码认证: $password_auth (已关闭)"
    echo "公钥认证: yes (仅公钥认证)"
    echo "Root 登录: $root_login (仅公钥)"
    echo "配置备份: $backup_path"
    echo "服务器 IP: $server_ip"
    echo "========================================"
    echo
    warn "重要提醒:"
    echo "1. SSH已配置为仅公钥认证，密码认证已关闭"
    if [[ "$CURRENT_USER" == "root" ]]; then
        echo "2. 已为 root 用户添加了 GitHub beiqi7 的公钥"
        echo "3. 仅允许 root 用户登录"
    else
        echo "2. 已为 root 和 $CURRENT_USER 用户添加了 GitHub beiqi7 的公钥"
        echo "3. 仅允许 root 和 $CURRENT_USER 用户登录"
    fi
    echo "4. 请确保已保存对应的私钥文件"
    echo "5. 测试连接: ssh -p $ssh_port root@$server_ip"
    echo "6. 如遇问题，可使用应急恢复: curl -sSL https://raw.githubusercontent.com/beiqi7/ssh-security/main/setup.sh | sudo bash -s -- --recover"
    echo "7. 或手动恢复: sudo bash setup.sh --recover"
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
