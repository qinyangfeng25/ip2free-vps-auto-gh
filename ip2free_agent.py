#!/usr/bin/env python3
"""
ip2free-vps-auto
=================
自动从 ip2free.com 获取最新住宅代理，并配置到 VPS 系统出口。

工作流程:
  1. 登录 ip2free 账号
  2. 自动领取可领取的活动奖励
  3. 获取免费/活动代理列表
  4. 逐一验证代理是否可用
  5. 将可用的代理写入 redsocks 配置
  6. 重启 redsocks + 更新 iptables 规则
  7. 验证系统出口 IP 是否为住宅 IP

支持定时自动刷新（通过 systemd timer 或 cron）。

用法:
  python ip2free_agent.py run          # 完整流程
  python ip2free_agent.py run --force  # 强制刷新
  python ip2free_agent.py fetch        # 仅获取代理列表
  python ip2free_agent.py status       # 查看当前代理状态
  python ip2free_agent.py verify       # 验证当前代理
  python ip2free_agent.py iptables     # 仅设置 iptables 规则
  python ip2free_agent.py clean        # 清理 iptables 规则
"""

import argparse
import json
import logging
import os
import random
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    print("[ERROR] 需要 requests 库，请运行: pip install requests")
    sys.exit(1)


# ==================== 常量 ====================

SCRIPT_DIR = Path(__file__).resolve().parent
ENV_FILE = SCRIPT_DIR / ".env"
DATA_DIR = SCRIPT_DIR / "data"
REDSOCKS_CONF = SCRIPT_DIR / "redsocks.conf"
PROXY_STATE_FILE = DATA_DIR / "proxy_state.json"
LOG_FILE = DATA_DIR / "ip2free-agent.log"

API_BASE = "https://api.ip2free.com"

DEFAULT_HEADERS = {
    "webname": "IP2FREE",
    "domain": "www.ip2free.com",
    "lang": "cn",
    "referer": "https://www.ip2free.com/",
    "origin": "https://www.ip2free.com",
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "content-type": "text/plain;charset=UTF-8",
}

IPTABLES_CHAIN = "IP2FREE_AUTO"


# ==================== 颜色输出 ====================

class Color:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def green(msg):
    return f"{Color.GREEN}{msg}{Color.RESET}"


def yellow(msg):
    return f"{Color.YELLOW}{msg}{Color.RESET}"


def red(msg):
    return f"{Color.RED}{msg}{Color.RESET}"


def blue(msg):
    return f"{Color.BLUE}{msg}{Color.RESET}"


def cyan(msg):
    return f"{Color.CYAN}{msg}{Color.RESET}"


def bold(msg):
    return f"{Color.BOLD}{msg}{Color.RESET}"


def log_info(msg):
    print(f"  {blue('ℹ')}  {msg}")


def log_ok(msg):
    print(f"  {green('✓')}  {msg}")


def log_warn(msg):
    print(f"  {yellow('⚠')}  {msg}")


def log_error(msg):
    print(f"  {red('✗')}  {msg}")


def log_step(msg):
    print(f"\n  {cyan('→')}  {bold(msg)}")


# ==================== 配置 ====================

class Config:
    """读取 .env 配置文件"""

    DEFAULTS = {
        "IP2FREE_EMAIL": "",
        "IP2FREE_PASSWORD": "",
        "IP2FREE_PROXY_SOURCE": "both",  # free / activity / both
        "IP2FREE_SELECT_STRATEGY": "first",  # first / random / country:XX
        "IP2FREE_COUNTRY_FILTER": "",
        "IP2FREE_CITY_FILTER": "",
        "IP2FREE_AUTO_CLAIM_REWARDS": "true",
        "IP2FREE_MAX_RETRIES": "5",
        "REDSOCKS_PORT": "12345",
        "REDSOCKS_LOG_LEVEL": "on",  # on / off
        "IP2FREE_CONFIG_PATH": "",
        "IP2FREE_OUTPUT_FORMAT": "txt",  # txt / yaml
    }

    def __init__(self, env_path=None):
        self.env_path = Path(env_path or ENV_FILE)
        self._values = dict(self.DEFAULTS)
        self._load()

    def _load(self):
        if not self.env_path.exists():
            log_warn(f"配置文件不存在: {self.env_path}")
            log_warn("请先复制 .env.example 为 .env 并填写你的 ip2free 账号密码")
            return

        for raw_line in self.env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            # 去掉引号
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            self._values[key] = value

    def get(self, key, default=None):
        return self._values.get(key, default) or default or ""

    def get_int(self, key, default=0):
        try:
            return int(self.get(key, str(default)))
        except ValueError:
            return default

    def get_bool(self, key, default=True):
        val = str(self.get(key, "")).strip().lower()
        if val in ("0", "false", "no", "off"):
            return False
        return bool(val)

    def validate(self):
        email = self.get("IP2FREE_EMAIL")
        password = self.get("IP2FREE_PASSWORD")
        if not email or not password:
            return False, "请在 .env 中设置 IP2FREE_EMAIL 和 IP2FREE_PASSWORD"
        return True, ""


# ==================== ip2free API 客户端 ====================

class IP2FreeAPI:
    """ip2free.com API 客户端"""

    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.token = None

    def _post(self, endpoint, data=None, timeout=30):
        """Call the provider API using an explicit JSON request body."""
        resp = self.session.post(
            f"{API_BASE}/api{endpoint}",
            json=data or {},
            timeout=timeout,
        )
        resp.raise_for_status()
        try:
            result = resp.json()
        except ValueError as exc:
            raise APIError(f"{endpoint} 返回了非 JSON 响应 (HTTP {resp.status_code})") from exc
        if not isinstance(result, dict):
            raise APIError(f"{endpoint} 返回格式异常: 顶层不是对象")
        return result

    def _check_response(self, result, endpoint, allow_business_error=False):
        code = result.get("code", 0)
        msg = result.get("msg", "")
        if code != 0 and not allow_business_error:
            raise APIError(f"{endpoint} 失败: {msg} (code={code})")
        return result

    def login(self):
        email = self.config.get("IP2FREE_EMAIL")
        password = self.config.get("IP2FREE_PASSWORD")

        result = self._post("/account/login", {"email": email, "password": password})
        self._check_response(result, "/account/login")

        self.token = result.get("data", {}).get("token")
        if not self.token:
            raise APIError("登录成功但未获取到 token")

        # 设置 token 到后续请求
        self.session.headers["x-token"] = self.token
        self.session.headers["X-Token"] = self.token
        log_ok("登录 ip2free 成功")
        return self.token

    def claim_activity_rewards(self, task_name_contains=None):
        """自动领取可领取的活动奖励"""
        result = self._post("/account/taskList", {})
        self._check_response(result, "/account/taskList")

        task_list = result.get("data", {}).get("list", []) or []
        claimed = []

        for task in task_list:
            task_name = task.get("task_name", "")
            task_code = task.get("task_code", "")
            if task.get("is_finished") == 1:
                continue
            if task_name_contains and task_name_contains not in task_name:
                continue
            if task_code != "client_click":
                continue

            task_id = task.get("id")
            if not task_id:
                continue

            try:
                finish_result = self._post(
                    "/account/finishTask",
                    {"id": task_id},
                )
                finish_code = finish_result.get("code", -999)
                if finish_code == 0:
                    log_ok(f"领取奖励: {task_name}")
                    claimed.append(task_name)
                elif finish_code == -1:
                    log_info(f"已完成: {task_name}")
                else:
                    log_warn(f"领取失败: {task_name} ({finish_result.get('msg', '')})")
            except Exception as e:
                log_warn(f"领取任务出错: {task_name} - {e}")

        if claimed:
            log_info(f"共领取 {len(claimed)} 个活动奖励")
        else:
            log_info("没有需要自动领取的活动奖励")
        return claimed

    def get_free_proxies(self):
        """获取免费代理列表（分页）"""
        all_proxies = []
        page = 1
        page_size = 100

        while True:
            result = self._post(
                "/ip/freeList",
                {
                    "keyword": self.config.get("IP2FREE_CITY_FILTER", ""),
                    "country": self.config.get("IP2FREE_COUNTRY_FILTER", ""),
                    "city": self.config.get("IP2FREE_CITY_FILTER", ""),
                    "page": page,
                    "page_size": page_size,
                },
            )
            self._check_response(result, "/ip/freeList")

            data = result.get("data") or {}
            if not isinstance(data, dict):
                raise APIError(f"/ip/freeList 返回 data 格式异常: {type(data).__name__}")
            # The provider has used both names across frontend revisions.
            proxy_list = (
                data.get("free_ip_list") or data.get("freeIpList") or
                data.get("list") or data.get("records") or []
            )
            if not isinstance(proxy_list, list):
                raise APIError("/ip/freeList 返回代理列表格式异常")
            if not proxy_list:
                break

            for proxy in proxy_list:
                proxy["source"] = "free"
                all_proxies.append(proxy)

            if len(proxy_list) < page_size:
                break
            page += 1
            if page > 10:
                break

        log_info(f"获取到 {len(all_proxies)} 个免费代理")
        return all_proxies

    def get_activity_proxies(self):
        """获取活动奖励代理列表（分页）"""
        all_proxies = []
        page = 1
        page_size = 100

        while True:
            try:
                result = self._post(
                    "/ip/taskIpList",
                    {
                        "keyword": self.config.get("IP2FREE_CITY_FILTER", ""),
                        "country": self.config.get("IP2FREE_COUNTRY_FILTER", ""),
                        "city": self.config.get("IP2FREE_CITY_FILTER", ""),
                        "page": page,
                        "page_size": page_size,
                    },
                    timeout=30,
                )
            except APIError:
                break

            code = result.get("code")
            if code not in (0, None):
                msg = result.get("msg", f"code={code}")
                log_info(f"活动代理接口: {msg}")
                break

            data = result.get("data") or {}
            if not isinstance(data, dict):
                raise APIError(f"/ip/taskIpList 返回 data 格式异常: {type(data).__name__}")
            page_data = data.get("page") or data
            if not isinstance(page_data, dict):
                raise APIError("/ip/taskIpList 返回分页格式异常")
            proxy_list = (
                page_data.get("list") or page_data.get("task_ip_list") or
                page_data.get("taskIpList") or page_data.get("records") or []
            )
            if not isinstance(proxy_list, list):
                raise APIError("/ip/taskIpList 返回代理列表格式异常")
            if not proxy_list:
                break

            for proxy in proxy_list:
                proxy["source"] = "activity"
                # 解析 contents 字段（可能包含额外的代理信息）
                contents = proxy.get("contents")
                if contents and proxy.get("provider_id") == 1:
                    try:
                        parsed = json.loads(contents)
                        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                            proxy.update(parsed[0])
                    except (json.JSONDecodeError, TypeError):
                        pass
                all_proxies.append(proxy)

            total_row = 0
            try:
                total_row = int(page_data.get("totalRow", 0))
            except (TypeError, ValueError):
                pass

            if len(proxy_list) < page_size:
                break
            if total_row and len(all_proxies) >= total_row:
                break
            page += 1
            if page > 10:
                break

        log_info(f"获取到 {len(all_proxies)} 个活动代理")
        return all_proxies

    def get_all_proxies(self):
        """获取所有代理（根据配置决定来源）"""
        source_mode = self.config.get("IP2FREE_PROXY_SOURCE", "both").lower()
        proxies = []

        if source_mode in ("free", "both"):
            proxies.extend(self.get_free_proxies())
        if source_mode in ("activity", "both"):
            proxies.extend(self.get_activity_proxies())

        if not proxies:
            raise APIError("没有获取到任何代理，请检查账号是否有可用代理")

        log_ok(f"共获取 {len(proxies)} 个代理")
        return proxies


class APIError(Exception):
    pass


# ==================== 代理选择器 ====================

class ProxySelector:
    """从代理列表中选择一个可用的代理"""

    @staticmethod
    def _normalize(proxy):
        """标准化代理数据"""
        return {
            "ip": proxy.get("ip") or proxy.get("host", ""),
            "port": int(proxy.get("port", 0) or 0),
            "username": proxy.get("username", ""),
            "password": proxy.get("password", ""),
            "protocol": (proxy.get("protocol") or "socks5").lower(),
            "source": proxy.get("source", "unknown"),
            "country": proxy.get("country_code") or proxy.get("country", "XX"),
            "city": proxy.get("city", "unknown"),
            "id": proxy.get("id") or proxy.get("task_id", 0),
        }

    @staticmethod
    def select(proxies, strategy="first", max_retries=5):
        """
        选择策略:
          first   - 选择第一个
          random  - 随机选择
          country:XX - 优先选择指定国家的代理
        """
        normalized = [ProxySelector._normalize(p) for p in proxies]
        normalized = [p for p in normalized if p["ip"] and p["port"]]

        if not normalized:
            raise ValueError("没有有效的代理数据")

        # 按策略排序
        if strategy.startswith("country:"):
            target_country = strategy.split(":", 1)[1].strip().upper()
            normalized.sort(key=lambda p: 0 if p["country"] == target_country else 1)
        elif strategy == "random":
            random.shuffle(normalized)

        # 尝试前 max_retries 个代理
        return normalized[:max_retries]


# ==================== 代理验证 ====================

class ProxyVerifier:
    """验证代理是否可用"""

    TEST_URL = "https://ifconfig.me"
    IP_PATTERN = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

    @staticmethod
    def verify(proxy, timeout=10):
        """验证单个代理，返回 (success, detected_ip, error_msg)"""
        ip = proxy["ip"]
        port = proxy["port"]
        username = proxy["username"]
        password = proxy["password"]
        protocol = proxy["protocol"]

        if protocol == "socks5":
            auth = f"{urllib.parse.quote(str(username), safe='')}:{urllib.parse.quote(str(password), safe='')}"
            proxy_url = f"socks5h://{auth}@{ip}:{port}"
        else:
            auth = f"{urllib.parse.quote(str(username), safe='')}:{urllib.parse.quote(str(password), safe='')}"
            proxy_url = f"http://{auth}@{ip}:{port}"

        proxies = {"http": proxy_url, "https": proxy_url}

        try:
            resp = requests.get(
                ProxyVerifier.TEST_URL,
                proxies=proxies,
                timeout=timeout,
                headers={"User-Agent": "curl/8.0.0"},
            )
            detected = ProxyVerifier.IP_PATTERN.search(resp.text)
            detected_ip = detected.group(0) if detected else ""
            success = resp.status_code == 200 and bool(detected_ip)
            return success, detected_ip, ""
        except requests.exceptions.Timeout:
            return False, "", "超时"
        except requests.exceptions.ConnectionError as e:
            return False, "", f"连接失败: {e}"
        except Exception as e:
            return False, "", str(e)


# ==================== redsocks 管理 ====================

class RedsocksManager:
    """管理 redsocks 配置和服务"""

    REDSOCKS_CONF_TEMPLATE = """\
base {{
    log_debug = off;
    log_info = {log_level};
    daemon = on;
    redirector = iptables;
}}

redsocks {{
    local_ip = 127.0.0.1;
    local_port = {local_port};

    ip = "{proxy_ip}";
    port = {proxy_port};
    type = {proxy_type};

    login = "{proxy_user}";
    password = "{proxy_pass}";
}}
"""

    PROTOCOL_MAP = {
        "socks5": "socks5",
        "http": "http_connect",
        "ss5": "ss5",
        "socks4": "socks4",
    }

    def __init__(self, config):
        self.config = config
        self.redsocks_conf = REDSOCKS_CONF

    def _get_redsocks_binary(self):
        """查找 redsocks 可执行文件"""
        for name in ("redsocks", "redsocks2"):
            path = shutil.which(name)
            if path:
                return path
        return None

    def _get_redsocks_service(self):
        """查找 redsocks systemd 服务名"""
        for name in ("redsocks", "redsocks2"):
            try:
                subprocess.run(
                    ["systemctl", "is-active", name],
                    capture_output=True, timeout=5,
                )
                return name
            except (subprocess.SubprocessError, FileNotFoundError):
                continue
        return None

    def generate_config(self, proxy):
        """生成 redsocks 配置文件内容"""
        proxy_type = self.PROTOCOL_MAP.get(proxy["protocol"], "socks5")
        return self.REDSOCKS_CONF_TEMPLATE.format(
            log_level=self.config.get("REDSOCKS_LOG_LEVEL", "on"),
            local_port=self.config.get("REDSOCKS_PORT", "12345"),
            proxy_ip=proxy["ip"],
            proxy_port=proxy["port"],
            proxy_type=proxy_type,
            proxy_user=proxy["username"],
            proxy_pass=proxy["password"],
        )

    def write_config(self, proxy):
        """Write the configuration used by both the app and systemd."""
        content = self.generate_config(proxy)
        self.redsocks_conf.write_text(content, encoding="utf-8")
        # Ubuntu's packaged redsocks service reads /etc/redsocks.conf, not the
        # file beside this program.  Keeping only the latter caused the service
        # and saved proxy state to drift apart.
        system_conf = Path("/etc/redsocks.conf")
        tmp_conf = system_conf.with_suffix(".conf.tmp")
        tmp_conf.write_text(content, encoding="utf-8")
        os.chmod(tmp_conf, 0o600)
        tmp_conf.replace(system_conf)
        log_ok(f"redsocks 配置已写入: {self.redsocks_conf}")
        return content

    def restart(self):
        """重启 redsocks 服务"""
        service_name = self._get_redsocks_service()

        if service_name:
            log_info(f"重启 redsocks 服务 ({service_name})...")
            try:
                subprocess.run(
                    ["systemctl", "restart", service_name],
                    check=True, timeout=10,
                )
                log_ok(f"redsocks ({service_name}) 重启成功")
                return True
            except subprocess.CalledProcessError as e:
                log_error(f"redsocks 重启失败: {e}")
                return False

        # fallback: 直接用二进制启动
        binary = self._get_redsocks_binary()
        if not binary:
            log_error("找不到 redsocks 可执行文件，请先安装 redsocks")
            return False

        log_info(f"使用二进制启动 redsocks: {binary}")
        try:
            subprocess.run(
                [binary, "-c", str(self.redsocks_conf)],
                check=True, timeout=10,
            )
            log_ok("redsocks 启动成功")
            return True
        except subprocess.CalledProcessError as e:
            log_error(f"redsocks 启动失败: {e}")
            return False

    def is_installed(self):
        """检查 redsocks 是否已安装"""
        return self._get_redsocks_binary() is not None


# ==================== iptables 管理 ====================

class IptablesManager:
    """管理 iptables NAT 规则"""

    def __init__(self, config):
        self.config = config
        self.local_port = self.config.get("REDSOCKS_PORT", "12345")

    def _run_iptables(self, args, check=True):
        """执行 iptables 命令"""
        cmd = ["iptables", "-t", "nat"] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if check and result.returncode != 0:
                return False, result.stderr.strip()
            return True, result.stderr.strip()
        except FileNotFoundError:
            return False, "iptables 命令不存在"
        except subprocess.TimeoutExpired:
            return False, "iptables 超时"

    def _ensure_chain(self):
        """确保自定义链存在"""
        ok, err = self._run_iptables(["-N", IPTABLES_CHAIN], check=False)
        if not ok and "already exists" not in err.lower():
            if "No chain/target/match by that name" not in err:
                log_warn(f"创建 iptables 链时出错: {err}")
        return True

    def _remove_jump(self):
        """移除 OUTPUT 链中的跳转规则"""
        self._run_iptables(
            ["-D", "OUTPUT", "-p", "tcp", "-j", IPTABLES_CHAIN],
            check=False,
        )

    def _add_jump(self):
        """在 OUTPUT 链添加跳转规则"""
        ok, err = self._run_iptables(
            ["-I", "OUTPUT", "1", "-p", "tcp", "-j", IPTABLES_CHAIN],
            check=False,
        )
        if not ok:
            log_warn(f"添加跳转规则失败: {err}")
        return ok

    def setup(self, proxy_ip=None):
        """设置 iptables 规则"""
        self._ensure_chain()

        # 清空并重建链
        self._run_iptables(["-F", IPTABLES_CHAIN], check=False)

        # 跳过 localhost
        self._run_iptables(
            ["-A", IPTABLES_CHAIN, "-d", "127.0.0.1/8", "-j", "RETURN"],
            check=False,
        )

        # 跳过私有地址
        for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            self._run_iptables(
                ["-A", IPTABLES_CHAIN, "-d", net, "-j", "RETURN"],
                check=False,
            )

        # 跳过代理服务器本身
        if proxy_ip:
            self._run_iptables(
                ["-A", IPTABLES_CHAIN, "-d", proxy_ip, "-j", "RETURN"],
                check=False,
            )

        # 重定向到 redsocks
        self._run_iptables(
            ["-A", IPTABLES_CHAIN, "-p", "tcp", "-j", "REDIRECT", "--to-ports", self.local_port],
            check=False,
        )

        # 添加 OUTPUT 跳转
        self._remove_jump()
        self._add_jump()

        log_ok("iptables 规则设置完成")
        return True

    def clean(self):
        """清理所有 iptables 规则"""
        self._remove_jump()
        self._run_iptables(["-F", IPTABLES_CHAIN], check=False)
        self._run_iptables(["-X", IPTABLES_CHAIN], check=False)
        log_ok("iptables 规则已清理")
        return True

    def verify(self):
        """验证 iptables 规则是否生效"""
        ok, _ = self._run_iptables(["-L", IPTABLES_CHAIN, "-n"], check=False)
        if not ok:
            return False
        return True

    def status(self):
        """显示当前 iptables 规则"""
        try:
            result = subprocess.run(
                ["iptables", "-t", "nat", "-L", IPTABLES_CHAIN, "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return ""


# ==================== 状态管理 ====================

class StateManager:
    """管理代理状态文件"""

    def __init__(self):
        self.state_file = PROXY_STATE_FILE
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

    def save(self, proxy):
        """保存当前代理状态"""
        state = {
            "ip": proxy["ip"],
            "port": proxy["port"],
            "username": proxy["username"],
            "password": proxy["password"],
            "protocol": proxy["protocol"],
            "source": proxy["source"],
            "country": proxy.get("country", "XX"),
            "city": proxy.get("city", "unknown"),
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.state_file.write_text(
            json.dumps(state, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        log_ok(f"代理状态已保存: {self.state_file}")

    def load(self):
        """加载当前代理状态"""
        if not self.state_file.exists():
            return None
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, IOError):
            return None

    def has_changed(self, proxy):
        """检查代理是否已变更"""
        state = self.load()
        if not state:
            return True
        return (
            state.get("ip") != proxy["ip"]
            or state.get("port") != proxy["port"]
        )


# ==================== 系统出口验证 ====================

class SystemVerifier:
    """验证系统出口 IP"""

    @staticmethod
    def get_exit_ip():
        """获取当前系统出口 IP，强制走 IPv4，避免 IPv6 偏好影响验证结果"""
        try:
            resp = requests.get(
                "https://ifconfig.me",
                timeout=10,
                headers={"User-Agent": "ip2free-agent/1.0"},
                proxies={"http": None, "https": None},
            )
            if resp.status_code == 200:
                match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", resp.text)
                if match:
                    return match.group(0)
        except Exception:
            pass

        try:
            import socket
            import http.client
            import ssl
            infos = socket.getaddrinfo("ifconfig.me", 443, socket.AF_INET, socket.SOCK_STREAM)
            addr = infos[0][4]
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(addr[0], timeout=10)
            conn.request("GET", "/", headers={"User-Agent": "ip2free-agent/1.0"})
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", "ignore")
            match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", body)
            conn.close()
            if match:
                return match.group(0)
        except Exception:
            pass
        return None

    @staticmethod
    def verify_system_exit(expected_ip=None):
        """验证系统出口是否为预期 IP"""
        actual_ip = SystemVerifier.get_exit_ip()
        if actual_ip:
            if expected_ip and actual_ip == expected_ip:
                return True, actual_ip, ""
            elif expected_ip:
                return False, actual_ip, f"期望 {expected_ip}，实际 {actual_ip}"
            else:
                return True, actual_ip, ""
        return False, "", "无法获取系统出口 IP"


# ==================== 主流程 ====================

def cmd_run(args):
    """完整流程：获取 + 配置 + 验证"""
    config = Config()

    ok, msg = config.validate()
    if not ok:
        log_error(msg)
        return False

    log_step("1/5 登录 ip2free 并获取代理")
    api = IP2FreeAPI(config)

    try:
        api.login()
    except APIError as e:
        log_error(f"登录失败: {e}")
        return False
    except requests.exceptions.RequestException as e:
        log_error(f"网络请求失败: {e}")
        return False

    # 自动领取活动奖励
    if config.get_bool("IP2FREE_AUTO_CLAIM_REWARDS", True):
        try:
            api.claim_activity_rewards()
        except Exception as e:
            log_warn(f"领取活动奖励出错: {e}")

    # 获取代理
    try:
        proxies = api.get_all_proxies()
    except APIError as e:
        log_error(f"获取代理失败: {e}")
        return False

    strategy = args.select or config.get("IP2FREE_SELECT_STRATEGY", "first")
    max_retries = args.retries or config.get_int("IP2FREE_MAX_RETRIES", 5)

    log_step("2/5 选择并验证代理")
    try:
        candidates = ProxySelector.select(proxies, strategy=strategy, max_retries=max_retries)
    except ValueError as e:
        log_error(str(e))
        return False

    selected_proxy = None
    for i, proxy in enumerate(candidates, 1):
        log_info(f"验证代理 [{i}/{len(candidates)}] {proxy['ip']}:{proxy['port']} ({proxy['protocol']})")
        success, detected_ip, err = ProxyVerifier.verify(proxy)
        if success:
            selected_proxy = proxy
            log_ok(f"代理可用! 出口 IP: {detected_ip}")
            break
        else:
            log_warn(f"代理不可用: {err}")

    if not selected_proxy:
        log_error(f"所有 {len(candidates)} 个代理都不可用")
        return False

    # 检查是否需要更新
    state_mgr = StateManager()
    if not args.force and not state_mgr.has_changed(selected_proxy):
        log_info("代理未变更，跳过更新")
        log_info("如需强制刷新，请添加 --force 参数")
        return True

    log_step("3/5 配置 redsocks")
    redsocks_mgr = RedsocksManager(config)

    if not redsocks_mgr.is_installed():
        log_error("redsocks 未安装，请先运行 install.sh")
        return False

    redsocks_mgr.write_config(selected_proxy)

    log_step("4/5 重启 redsocks 并设置 iptables")
    if not redsocks_mgr.restart():
        log_warn("redsocks 重启可能失败，继续尝试...")

    # Transparent redirection is opt-in.  A verified SOCKS endpoint can still
    # fail under redsocks, and redirecting every TCP connection would then
    # strand the server.  The web panel applies narrowly scoped rules instead.
    if args.apply_iptables:
        iptables_mgr = IptablesManager(config)
        iptables_mgr.setup(proxy_ip=selected_proxy["ip"])

    # 保存状态
    state_mgr.save(selected_proxy)

    log_step("5/5 验证系统出口")
    time.sleep(2)  # 等待 redsocks 生效

    # The proxy gateway address is not necessarily the egress address (NAT,
    # load balancing and residential pools are common), so equality is not a
    # valid health check.  ProxyVerifier already verified this specific proxy.
    success, actual_ip, err = SystemVerifier.verify_system_exit()

    if success:
        log_ok(f"系统出口 IP 已切换为: {bold(actual_ip)}")
        log_info(f"协议: {selected_proxy['protocol']} | 来源: {selected_proxy['source']}")
        log_info(f"国家: {selected_proxy.get('country', 'N/A')} | 城市: {selected_proxy.get('city', 'N/A')}")
        print()
        print(f"  {green('🎉')}  {bold('代理配置完成!')}")
        return True
    else:
        log_warn(f"系统出口验证: {err}")
        # In whitelist mode the IP echo endpoint is intentionally direct, and
        # providers may also block it.  The selected proxy was already tested
        # by ProxyVerifier above, so this must not turn a successful refresh
        # into a failed scheduled task.
        log_warn("代理已通过上游验证；无法读取系统出口，不影响已配置的域名代理规则")
        print()
        print(f"  {green('🎉')}  {bold('代理配置完成（上游已验证）!')}")
        return True


def cmd_fetch(args):
    """仅获取代理列表"""
    config = Config()
    ok, msg = config.validate()
    if not ok:
        log_error(msg)
        return False

    api = IP2FreeAPI(config)
    try:
        api.login()
        proxies = api.get_all_proxies()
    except (APIError, requests.exceptions.RequestException) as e:
        log_error(f"获取代理失败: {e}")
        return False

    _header = bold(f"共获取 {len(proxies)} 个代理:")
    print(f"\n  {_header}\n")
    for i, proxy in enumerate(proxies[:20], 1):
        p = ProxySelector._normalize(proxy)
        print(f"    [{i:3d}] {p['ip']:>15} : {p['port']:<6} {p['protocol']:<8} "
              f"{p['country']:>3} {p['city']:<20} [{p['source']}]")

    if len(proxies) > 20:
        print(f"    ... 还有 {len(proxies) - 20} 个代理")
    print()
    return True


def cmd_status(args):
    """查看当前代理状态"""
    state_mgr = StateManager()
    state = state_mgr.load()

    if not state:
        log_warn("没有已保存的代理状态，请先运行 'run' 命令")
        return False

    _status_header = bold("当前代理状态:")
    print(f"\n  {_status_header}\n")
    print(f"    IP:      {state['ip']}")
    print(f"    端口:    {state['port']}")
    print(f"    协议:    {state['protocol']}")
    print(f"    来源:    {state.get('source', 'N/A')}")
    print(f"    国家:    {state.get('country', 'N/A')}")
    print(f"    城市:    {state.get('city', 'N/A')}")
    print(f"    更新时间: {state.get('updated_at', 'N/A')}")
    print()

    # 检查系统出口
    success, actual_ip, err = SystemVerifier.verify_system_exit(expected_ip=state["ip"])
    if success:
        print(f"    系统出口: {green(actual_ip)}")
    else:
        print(f"    系统出口: {red(actual_ip or err)}")
    print()

    # 检查 redsocks
    config = Config()
    redsocks_mgr = RedsocksManager(config)
    if redsocks_mgr.is_installed():
        service = redsocks_mgr._get_redsocks_service()
        if service:
            try:
                r = subprocess.run(
                    ["systemctl", "is-active", service],
                    capture_output=True, text=True, timeout=5,
                )
                status = r.stdout.strip()
                print(f"    redsocks:  {green(status) if status == 'active' else red(status)}")
            except Exception:
                print(f"    redsocks:  {yellow('unknown')}")
    print()
    return True


def cmd_verify(args):
    """验证当前代理"""
    state_mgr = StateManager()
    state = state_mgr.load()

    if not state:
        log_warn("没有已保存的代理状态")
        return False

    proxy = {
        "ip": state["ip"],
        "port": state["port"],
        "username": state["username"],
        "password": state["password"],
        "protocol": state["protocol"],
    }

    print(f"  验证代理: {proxy['ip']}:{proxy['port']}")
    success, detected_ip, err = ProxyVerifier.verify(proxy)

    if success:
        print(f"  {green('✓')} 代理可用，出口 IP: {detected_ip}")
        return True
    else:
        print(f"  {red('✗')} 代理不可用: {err}")
        return False


def cmd_iptables(args):
    """设置 iptables 规则"""
    config = Config()
    state_mgr = StateManager()
    state = state_mgr.load()

    proxy_ip = state["ip"] if state else None
    iptables_mgr = IptablesManager(config)

    if args.action == "setup":
        iptables_mgr.setup(proxy_ip=proxy_ip)
    elif args.action == "clean":
        iptables_mgr.clean()
    elif args.action == "status":
        rules = iptables_mgr.status()
        if rules:
            _iptables_header = bold("iptables NAT 规则 (IP2FREE_AUTO):")
            print(f"\n  {_iptables_header}\n")
            for line in rules.splitlines():
                print(f"    {line}")
        else:
            log_warn("没有找到 ip2free iptables 规则")
    return True


def cmd_clean(args):
    """清理所有规则"""
    config = Config()
    iptables_mgr = IptablesManager(config)
    iptables_mgr.clean()
    log_ok("清理完成")
    return True


# ==================== CLI ====================

def main():
    parser = argparse.ArgumentParser(
        description="ip2free VPS 住宅代理自动配置工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python ip2free_agent.py run              # 完整流程
  python ip2free_agent.py run --force      # 强制刷新
  python ip2free_agent.py run --select random  # 随机选择代理
  python ip2free_agent.py status           # 查看状态
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # run
    run_parser = subparsers.add_parser("run", help="完整流程：获取+配置+验证")
    run_parser.add_argument("--force", action="store_true", help="强制刷新代理")
    run_parser.add_argument("--apply-iptables", action="store_true", help="显式启用透明 iptables 重定向（高风险）")
    run_parser.add_argument("--no-iptables", action="store_true", help=argparse.SUPPRESS)
    run_parser.add_argument("--select", help="选择策略: first / random / country:XX")
    run_parser.add_argument("--retries", type=int, help="最多尝试几个代理")

    # fetch
    subparsers.add_parser("fetch", help="仅获取代理列表")

    # status
    subparsers.add_parser("status", help="查看当前代理状态")

    # verify
    subparsers.add_parser("verify", help="验证当前代理")

    # iptables
    ipt_parser = subparsers.add_parser("iptables", help="管理 iptables 规则")
    ipt_parser.add_argument("action", choices=["setup", "clean", "status"], help="操作")

    # clean
    subparsers.add_parser("clean", help="清理所有规则")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return False

    commands = {
        "run": cmd_run,
        "fetch": cmd_fetch,
        "status": cmd_status,
        "verify": cmd_verify,
        "iptables": cmd_iptables,
        "clean": cmd_clean,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)
    return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
