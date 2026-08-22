# ip2free-vps-auto

自动从 [ip2free.com](https://ip2free.com) 获取最新住宅代理，并配置到 VPS 系统出口，让 VPS 的所有出网流量显示为住宅 IP。

支持每天定时自动刷新（09:00 / 15:00 / 20:00），无需手动操作。


## 工作原理

```
┌─────────┐     ┌──────────────┐     ┌──────────────┐     ┌───────────┐
│  VPS 上  │     │  redsocks    │     │  ip2free     │     │   目标    │
│  的应用   │ ──→ │  (本地代理)   │ ──→ │  住宅代理    │ ──→ │   网站    │
│  (x-ui)  │     │  127.0.0.1   │     │  住宅IP:端口  │     │           │
└─────────┘     │  :12345      │     └──────────────┘     └───────────┘
                │  SOCKS5      │
                └──────────────┘
```

1. **redsocks** 在 VPS 本地监听 `127.0.0.1:12345`，作为 SOCKS5 出口
2. **iptables** 将所有出网 TCP 流量重定向到 redsocks
3. redsocks 将流量转发到 ip2free 的住宅代理
4. 从目标网站看，流量来自住宅 IP


## 快速开始

### 方式一：一键安装（推荐）

```bash
# 在 VPS 上执行
cd /opt
git clone https://github.com/your-name/ip2free-vps-auto.git
cd ip2free-vps-auto

# 或使用 scp 上传整个目录到 VPS
chmod +x install.sh
sudo ./install.sh
```

安装脚本会：
- 自动安装 Python3、redsocks、iptables 等依赖
- 部署程序文件到 `/opt/ip2free-auto/`
- 创建 `.env` 配置文件（需你手动填写账号密码）
- 部署 Flask 管理面板、模板、静态资源和 `requirements.txt`
- 设置 systemd 定时器（每天 09:00/15:00/20:00 自动刷新）
- 启用 `ip2free-panel.service` 管理面板服务
- 首次运行获取代理并配置

### 方式二：手动安装

```bash
# 1. 安装依赖
sudo apt install python3 python3-pip redsocks iptables curl   # Ubuntu/Debian
sudo yum install python3 python3-pip redsocks2 iptables-services curl  # CentOS

pip3 install requests

# 2. 部署文件
sudo mkdir -p /opt/ip2free-auto
sudo cp -r ./* /opt/ip2free-auto/

# 3. 配置 .env
sudo cp /opt/ip2free-auto/.env.example /opt/ip2free-auto/.env
sudo vim /opt/ip2free-auto/.env

# 修改:
#   IP2FREE_EMAIL=你的邮箱
#   IP2FREE_PASSWORD=你的密码

# 4. 设置 systemd 定时器
sudo cp ip2free-auto.service /etc/systemd/system/
sudo cp ip2free-auto.timer /etc/systemd/system/
sudo sed -i 's|/opt/ip2free-auto|/opt/ip2free-auto|g' /etc/systemd/system/ip2free-auto.service
sudo systemctl daemon-reload
sudo systemctl enable --now ip2free-auto.timer

# 5. 首次运行
cd /opt/ip2free-auto
python3 ip2free_agent.py run --force
```


## 配置文件 (.env)

```ini
# 必填：ip2free 登录信息
IP2FREE_EMAIL=your-actual-ip2free-email
IP2FREE_PASSWORD=your-actual-ip2free-password

# 代理来源: free / activity / both（推荐 both）
IP2FREE_PROXY_SOURCE=both

# 选择策略: first / random / country:US
IP2FREE_SELECT_STRATEGY=first

# 国家过滤（可选，留空不限制）
IP2FREE_COUNTRY_FILTER=

# 最多尝试几个代理
IP2FREE_MAX_RETRIES=5

# redsocks 端口
REDSOCKS_PORT=12345
```


## 常用命令

```bash
cd /opt/ip2free-auto

# 完整流程：获取代理 → 配置 → 验证
python3 ip2free_agent.py run

# 强制刷新（即使代理没变也重新获取）
python3 ip2free_agent.py run --force

# 随机选择一个代理
python3 ip2free_agent.py run --select random

# 优先选择美国代理
python3 ip2free_agent.py run --select country:US

# 查看当前代理状态
python3 ip2free_agent.py status

# 验证当前代理是否可用
python3 ip2free_agent.py verify

# 仅获取代理列表（不配置）
python3 ip2free_agent.py fetch

# 查看 iptables 规则
python3 ip2free_agent.py iptables status

# 清理所有规则（恢复 VPS 原始出口）
python3 ip2free_agent.py clean
```


## 定时任务

程序支持两种方式自动定时刷新：

### systemd timer（推荐）

```bash
# 查看定时器状态
systemctl list-timers ip2free-auto.timer

# 查看日志
journalctl -u ip2free-auto.service -f
```

### cron

如果 systemd 不可用，install.sh 会自动配置 cron 作为备选：

```bash
crontab -l | grep ip2free
```


## 验证是否生效

```bash
# 查看系统出口 IP（应该是住宅 IP）
curl https://ifconfig.me

# 查看当前代理状态
python3 ip2free_agent.py status
```

如果输出的是 ip2free 的住宅 IP，说明配置成功。


## 管理面板

项目包含一个本地 Flask 管理面板，用于查看状态、管理域名代理规则、查看日志和切换代理。

```bash
# 手工启动
cd /opt/ip2free-auto
python3 panel.py

# 或使用 systemd
sudo systemctl enable --now ip2free-panel.service
sudo systemctl status ip2free-panel
```

默认地址：`http://127.0.0.1:8889`

首次启动时，如果 `panel_config.json` 中没有设置面板密码，程序会自动生成随机密码并写入配置。
也可以通过环境变量设置：

```bash
PANEL_USERNAME=admin PANEL_PASSWORD=your-strong-password python3 panel.py
```

不要直接把面板端口暴露到公网；推荐通过 nginx 反代并开启 HTTPS。


## 脱敏与 GitHub 发布

这个仓库版本已经移除了本地虚拟环境、真实面板密码、本机绝对路径、解析缓存和运行日志。
上传前建议再检查一次：

```bash
rg -n "真实邮箱|真实密码|真实IP|本机绝对路径" .
```


## 故障排查

| 问题 | 原因 | 解决方法 |
|------|------|----------|
| 登录失败 | 邮箱或密码错误 | 检查 `.env` 中的账号密码 |
| 没有获取到代理 | 账号没有可用代理 | 登录 ip2free 后台查看，或完成活动任务获取 |
| redsocks 启动失败 | redsocks 未安装 | `apt install redsocks` 或 `yum install redsocks2` |
| 系统出口 IP 没变 | iptables 规则未生效 | `python3 ip2free_agent.py iptables status` 检查规则 |
| 定时任务不工作 | systemd/cron 未启用 | `systemctl status ip2free-auto.timer` 或 `crontab -l` |
| 所有代理都不可用 | 代理已过期或网络问题 | 等待下次刷新，或手动运行 `python3 ip2free_agent.py run --force` |


## 卸载

```bash
# 停止定时器
sudo systemctl disable --now ip2free-auto.timer

# 清理 iptables 规则
python3 ip2free_agent.py clean

# 删除文件
sudo rm -rf /opt/ip2free-auto
sudo rm /etc/systemd/system/ip2free-auto.service
sudo rm /etc/systemd/system/ip2free-auto.timer
sudo systemctl daemon-reload

# 清理 cron
crontab -l | grep -v ip2free | crontab -
```


## 目录结构

```
ip2free-vps-auto/
├── ip2free_agent.py          # 主程序
├── panel.py                  # 管理面板入口
├── domain_manager.py         # 域名规则与 iptables 规则引擎
├── .env.example              # 配置模板
├── panel_config.json         # 面板配置模板
├── requirements.txt          # Python 依赖
├── install.sh                # 一键安装脚本
├── ip2free-auto.service      # systemd 服务
├── ip2free-auto.timer        # systemd 定时器
├── ip2free-panel.service     # 管理面板 systemd 服务
├── data/                     # 数据目录（自动生成，不提交）
│   ├── proxy_state.json      # 当前代理状态
│   └── panel.log             # 面板日志
├── templates/                # 面板页面模板
├── static/                   # 面板静态资源
├── CODE_REVIEW.md            # 代码审查与发布说明
├── LICENSE                   # 许可证
├── .gitignore                # GitHub 排除规则
└── README.md                 # 本文件
```


## 注意事项

- ip2free 的免费代理有有效期（通常 24 小时），到期后需要重新获取
- 活动奖励代理需要完成对应任务才能获得
- 每天 09:00/15:00/20:00 自动刷新，如果代理已变更才会更新配置
- redsocks 只处理 TCP 流量，UDP 流量不受影响
- 如果 x-ui 使用 UDP 协议，可能需要额外的 UDP 代理方案
