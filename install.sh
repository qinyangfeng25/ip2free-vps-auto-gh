#!/usr/bin/env bash
set -euo pipefail

# =============================================
# ip2free-vps-auto 一键安装脚本
# =============================================
# 在 VPS 上运行此脚本，自动完成:
#   1. 安装依赖（Python3, redsocks, iptables）
#   2. 部署程序文件
#   3. 配置 .env 文件
#   4. 设置 redsocks 服务
#   5. 设置 systemd 定时任务（每天 9:00/15:00/20:00）
#   6. 首次运行获取代理
# =============================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/ip2free-auto"
LOG_FILE="/var/log/ip2free-auto.log"

RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
CYAN='\033[96m'
BOLD='\033[1m'
RESET='\033[0m'

info()  { echo -e "  ${BLUE}ℹ${RESET}  $1"; }
ok()    { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn()  { echo -e "  ${YELLOW}⚠${RESET}  $1"; }
error() { echo -e "  ${RED}✗${RESET}  $1"; }
step()  { echo -e "\n  ${CYAN}→${RESET}  ${BOLD}$1${RESET}"; }


# ==================== 检查 root ====================

if [[ $EUID -ne 0 ]]; then
    error "此脚本需要 root 权限，请使用 sudo 运行"
    exit 1
fi


# ==================== 检测系统 ====================

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="${ID}"
        OS_VERSION="${VERSION_ID}"
    elif [[ -f /etc/redhat-release ]]; then
        OS_ID="centos"
        OS_VERSION=$(grep -oP '\d+' /etc/redhat-release | head -1)
    else
        OS_ID="unknown"
        OS_VERSION=""
    fi
}


# ==================== 安装依赖 ====================

install_dependencies() {
    step "安装系统依赖"

    case "${OS_ID}" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq \
                python3 python3-pip python3-venv \
                redsocks \
                iptables \
                curl wget git \
                cron
            ;;
        centos|rhel|rocky|almalinux)
            # 尝试 EPEL
            yum install -y epel-release 2>/dev/null || true
            yum groupinstall -y "Development Tools" 2>/dev/null || true
            yum install -y \
                python3 python3-pip \
                redsocks2 \
                iptables-services \
                curl wget git \
                cronie
            # CentOS 上 redsocks2 是默认包名
            if ! command -v redsocks &>/dev/null && command -v redsocks2 &>/dev/null; then
                ln -sf "$(command -v redsocks2)" /usr/local/bin/redsocks 2>/dev/null || true
            fi
            ;;
        *)
            warn "未识别的系统: ${OS_ID}，尝试通用安装..."
            # 尝试 apt
            if command -v apt-get &>/dev/null; then
                apt-get update -qq
                apt-get install -y -qq python3 python3-pip redsocks iptables curl wget git cron
            elif command -v yum &>/dev/null; then
                yum install -y python3 python3-pip redsocks2 iptables-services curl wget git cronie
            else
                error "无法自动安装依赖，请手动安装: python3, redsocks, iptables"
                exit 1
            fi
            ;;
    esac

    ok "系统依赖安装完成"
}


# ==================== 安装 Python 依赖 ====================

install_python_deps() {
    step "安装 Python 依赖"

    # 尝试使用 venv
    python3 -m venv "${INSTALL_DIR}/venv" 2>/dev/null || true

    if [[ -d "${INSTALL_DIR}/venv" ]]; then
        # shellcheck disable=SC1091
        source "${INSTALL_DIR}/venv/bin/activate"
        pip install --quiet --upgrade pip
        pip install --quiet -r "${INSTALL_DIR}/requirements.txt"
        ok "Python 依赖安装完成（venv）"
    else
        pip3 install --quiet -r "${INSTALL_DIR}/requirements.txt" 2>/dev/null || pip install --quiet -r "${INSTALL_DIR}/requirements.txt"
        ok "Python 依赖安装完成（系统 pip）"
    fi
}


# ==================== 部署文件 ====================

deploy_files() {
    step "部署程序文件到 ${INSTALL_DIR}"

    mkdir -p "${INSTALL_DIR}"

    # 复制主脚本
    cp "${SCRIPT_DIR}/ip2free_agent.py" "${INSTALL_DIR}/"
    chmod +x "${INSTALL_DIR}/ip2free_agent.py"

    # 复制面板与管理文件
    cp "${SCRIPT_DIR}/panel.py" "${INSTALL_DIR}/"
    cp "${SCRIPT_DIR}/domain_manager.py" "${INSTALL_DIR}/"
    cp "${SCRIPT_DIR}/panel_config.json" "${INSTALL_DIR}/"
    cp -r "${SCRIPT_DIR}/templates" "${INSTALL_DIR}/"
    cp -r "${SCRIPT_DIR}/static" "${INSTALL_DIR}/"
    cp "${SCRIPT_DIR}/requirements.txt" "${INSTALL_DIR}/"

    # 复制配置文件模板
    cp "${SCRIPT_DIR}/.env.example" "${INSTALL_DIR}/.env.example"

    # 复制 systemd 文件
    cp "${SCRIPT_DIR}/ip2free-auto.service" /etc/systemd/system/ 2>/dev/null || true
    cp "${SCRIPT_DIR}/ip2free-auto.timer" /etc/systemd/system/ 2>/dev/null || true

    # 复制面板 systemd 文件（如果仓库中存在）
    if [[ -f "${SCRIPT_DIR}/ip2free-panel.service" ]]; then
        cp "${SCRIPT_DIR}/ip2free-panel.service" /etc/systemd/system/ 2>/dev/null || true
    fi

    # 创建数据目录
    mkdir -p "${INSTALL_DIR}/data"
    touch "${LOG_FILE}"

    ok "文件部署完成"
}


# ==================== 配置 .env ====================

configure_env() {
    step "配置 .env 文件"

    local env_file="${INSTALL_DIR}/.env"

    if [[ -f "${env_file}" ]]; then
        info ".env 文件已存在，跳过创建"
        info "如需修改，请编辑: ${env_file}"
        return
    fi

    cp "${INSTALL_DIR}/.env.example" "${env_file}"

    echo ""
    echo -e "  ${BOLD}请先编辑 .env 文件，填写你的 ip2free 账号密码${RESET}"
    echo ""
    echo "    ${BOLD}vim ${env_file}${RESET}"
    echo ""
    echo "    需要修改的字段:"
    echo "    - IP2FREE_EMAIL    : 你的 ip2free 登录邮箱"
    echo "    - IP2FREE_PASSWORD : 你的 ip2free 登录密码"
    echo ""
    echo -e "  ${YELLOW}编辑完成后，再次运行此脚本继续安装${RESET}"
    echo ""
    exit 0
}


# ==================== 配置 systemd ====================

setup_systemd() {
    step "配置 systemd 服务"

    # 修改 service 文件中的路径
    sed -i "s|/opt/ip2free-auto|${INSTALL_DIR}|g" /etc/systemd/system/ip2free-auto.service 2>/dev/null || true

    # 检查 venv
    if [[ -d "${INSTALL_DIR}/venv" ]]; then
        sed -i "s|ExecStart=.*|ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/ip2free_agent.py run --no-iptables|" \
            /etc/systemd/system/ip2free-auto.service 2>/dev/null || true
    else
        sed -i "s|ExecStart=.*|ExecStart=/usr/bin/python3 ${INSTALL_DIR}/ip2free_agent.py run --no-iptables|" \
            /etc/systemd/system/ip2free-auto.service 2>/dev/null || true
    fi

    systemctl daemon-reload

    # 启用定时器
    systemctl enable ip2free-auto.timer 2>/dev/null || true
    systemctl start ip2free-auto.timer 2>/dev/null || true

    if systemctl is-active --quiet ip2free-auto.timer 2>/dev/null; then
        ok "systemd 定时器已启用（每天 09:00 / 15:00 / 20:00）"
    else
        warn "systemd 定时器启用失败，将使用 cron 作为备选"
        setup_cron
    fi

    if [[ -f /etc/systemd/system/ip2free-panel.service ]]; then
        sed -i "s|/opt/ip2free-auto|${INSTALL_DIR}|g" /etc/systemd/system/ip2free-panel.service 2>/dev/null || true

        if [[ -d "${INSTALL_DIR}/venv" ]]; then
            sed -i "s|ExecStart=.*|ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/panel.py|" \
                /etc/systemd/system/ip2free-panel.service 2>/dev/null || true
        else
            sed -i "s|ExecStart=.*|ExecStart=/usr/bin/python3 ${INSTALL_DIR}/panel.py|" \
                /etc/systemd/system/ip2free-panel.service 2>/dev/null || true
        fi

        systemctl daemon-reload
        systemctl enable ip2free-panel.service 2>/dev/null || true
        systemctl start ip2free-panel.service 2>/dev/null || true
        ok "面板服务 ip2free-panel.service 已启用"
    fi
}


# ==================== 配置 cron 备选 ====================

setup_cron() {
    local cron_entry="0 9,15,20 * * * cd ${INSTALL_DIR} && /usr/bin/python3 ${INSTALL_DIR}/ip2free_agent.py run >> ${LOG_FILE} 2>&1"

    if crontab -l 2>/dev/null | grep -q "ip2free_agent.py"; then
        info "cron 任务已存在，跳过"
    else
        (crontab -l 2>/dev/null; echo "${cron_entry}") | crontab -
        ok "cron 定时任务已设置（每天 09:00 / 15:00 / 20:00）"
    fi
}


# ==================== 首次运行 ====================

first_run() {
    step "首次运行，获取代理并配置"

    local python_cmd="/usr/bin/python3"
    if [[ -d "${INSTALL_DIR}/venv" ]]; then
        python_cmd="${INSTALL_DIR}/venv/bin/python3"
    fi

    cd "${INSTALL_DIR}"

    if $python_cmd "${INSTALL_DIR}/ip2free_agent.py" run --force; then
        ok "首次运行成功!"
    else
        warn "首次运行遇到问题，请检查:"
        echo "    1. .env 文件中的账号密码是否正确"
        echo "    2. redsocks 是否正常运行: systemctl status redsocks"
        echo "    3. iptables 规则: iptables -t nat -L IP2FREE_AUTO -n"
    fi
}


# ==================== 主流程 ====================

main() {
    echo ""
    echo -e "  ${BOLD}${CYAN}ip2free-vps-auto 一键安装${RESET}"
    echo -e "  ${BOLD}自动获取 ip2free 住宅代理并配置 VPS 出口${RESET}"
    echo ""

    detect_os
    info "检测到系统: ${OS_ID} ${OS_VERSION}"

    install_dependencies
    deploy_files
    install_python_deps
    configure_env
    setup_systemd
    first_run

    echo ""
    echo -e "  ${GREEN}${BOLD}安装完成!${RESET}"
    echo ""
    echo "  常用命令:"
    echo "    cd ${INSTALL_DIR}"
    echo "    python3 ip2free_agent.py run       # 手动刷新代理"
    echo "    python3 ip2free_agent.py status    # 查看当前状态"
    echo "    python3 ip2free_agent.py verify    # 验证代理"
    echo "    python3 panel.py                   # 启动管理面板"
    echo "    systemctl status ip2free-panel     # 查看面板服务"
    echo "    python3 ip2free_agent.py clean     # 清理规则"
    echo ""
    echo "  日志文件: ${LOG_FILE}"
    echo "  配置文件: ${INSTALL_DIR}/.env"
    echo "  面板配置: ${INSTALL_DIR}/panel_config.json"
    echo "  管理面板: http://127.0.0.1:8889"
    echo ""
}

main "$@"
