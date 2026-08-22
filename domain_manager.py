#!/usr/bin/env python3
"""
Domain Rule Engine
===================
Manages domain-to-IP resolution and iptables rule generation.

Supports two modes:
  - blacklist: all traffic uses proxy, except bypass list (high risk)
  - whitelist (default): only listed domains use proxy, rest goes direct

Domain IPs are re-resolved whenever proxy rules are evaluated; the cache is
retained only as an audit/display snapshot.
"""

import json
import re
import socket
import threading
import time
from datetime import datetime
from pathlib import Path


DATA_DIR = Path(__file__).resolve().parent / "data"
RESOLVED_FILE = DATA_DIR / "resolved_domains.json"


class DomainManager:
    """Domain rule management with DNS resolution and iptables rule generation"""

    # Private/internal networks (always bypass)
    PRIVATE_NETS = [
        "127.0.0.1/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ]

    def __init__(self, config_path):
        self.config_path = Path(config_path)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._load_config()
        self._resolved_cache = {}
        self._lock = threading.Lock()
        self._load_cache()

    def _load_config(self):
        """Load configuration from JSON file"""
        default_config = {
            # A failed free proxy must never take the VPS offline.  Enable it
            # explicitly from the panel after adding the domains to proxy.
            "proxy_enabled": False,
            "proxy_mode": "whitelist",  # blacklist / whitelist
            "proxy_domains": [],         # domains that USE proxy (whitelist) or are forced
            "bypass_domains": [],       # domains that bypass proxy (blacklist exceptions)
            "ipv6_block_domains": [
                "oauthaccountmanager.googleapis.com",
                "lh3.googleusercontent.com",
                "robinfrontend-pa.googleapis.com",
                "notifications-pa.googleapis.com",
                "subscriptionsfirstparty-pa.googleapis.com",
                "signaler-pa.googleapis.com",
                "people-pa.googleapis.com",
                "oauth2.googleapis.com",
                "www.googleapis.com",
                "gemini.google.com",
                "notebooklm-pa.googleapis.com",
                "notebooklm.google.com",
                "<example-domain>.example",
            ],
            "proxy_strategy": "first",
            "proxy_source": "both",
            "max_retries": 5,
            "redsocks_port": 12345,
            "dns_ttl_seconds": 300,     # re-resolve every 5 minutes
            "auto_refresh_enabled": True,
            "auto_refresh_times": ["09:00", "15:00", "20:00"],
            "panel_port": 8889,
            "https_port": 8899,
            "panel_username": "admin",
            "panel_password": "",
            "log_file": str(DATA_DIR / "panel.log"),
        }

        if self.config_path.exists():
            try:
                saved = json.loads(self.config_path.read_text(encoding="utf-8"))
                default_config.update(saved)
            except (json.JSONDecodeError, IOError):
                pass

        self.config = default_config
        self._save_config()

    def _save_config(self):
        """Persist config to disk"""
        self.config_path.write_text(
            json.dumps(self.config, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _load_cache(self):
        """Load cached DNS resolutions"""
        if RESOLVED_FILE.exists():
            try:
                data = json.loads(RESOLVED_FILE.read_text(encoding="utf-8"))
                self._resolved_cache = data.get("resolutions", {})
                self._last_resolve_time = data.get("last_resolve", 0)
            except (json.JSONDecodeError, IOError):
                self._resolved_cache = {}
                self._last_resolve_time = 0
        else:
            self._resolved_cache = {}
            self._last_resolve_time = 0

    def _save_cache(self):
        """Save DNS resolutions to cache"""
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        RESOLVED_FILE.write_text(
            json.dumps({
                "resolutions": self._resolved_cache,
                "last_resolve": time.time(),
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def should_resolve_now(self):
        """Check if DNS re-resolution is needed"""
        if not self._resolved_cache:
            return True
        ttl = self.config.get("dns_ttl_seconds", 300)
        return time.time() - self._last_resolve_time > ttl

    def _resolve_domain(self, domain):
        """Resolve a single domain to IPv4 addresses"""
        try:
            addrs = set()
            infos = socket.getaddrinfo(domain, None, socket.AF_INET)
            for info in infos:
                addrs.add(info[4][0])
            return sorted(addrs)
        except Exception:
            return []

    def resolve_all_domains(self, domains):
        """Resolve all domains and cache results"""
        # Do not retain an address after DNS has stopped returning it.  Stale
        # addresses are especially dangerous here because they can redirect
        # unrelated traffic after a CDN rotation.
        active_domains = {domain for domain in domains if domain}
        for domain in list(self._resolved_cache):
            if domain not in active_domains:
                self._resolved_cache.pop(domain, None)
        for domain in domains:
            if domain:
                ips = self._resolve_domain(domain)
                if ips:
                    self._resolved_cache[domain] = ips
                else:
                    self._resolved_cache.pop(domain, None)

        self._last_resolve_time = time.time()
        self._save_cache()
        return self._resolved_cache

    def get_resolved_ips(self, domains, refresh=True):
        """Return the *current* IPv4 targets for a domain rule list.

        These addresses are used to generate transparent-proxy rules.  Keeping
        a TTL-only mapping here is unsafe for CDN-backed domains: a later
        request could resolve to a new address which would then miss the
        whitelist.  Therefore every rule evaluation refreshes DNS by default.
        The on-disk cache is retained solely for display/audit purposes, never
        as the authority for a new rule evaluation.
        """
        domains = [domain for domain in domains if domain]
        if refresh:
            self.resolve_all_domains(domains)
        elif self.should_resolve_now():
            self.resolve_all_domains(domains)

        all_ips = set()
        for domain in domains:
            if domain in self._resolved_cache:
                all_ips.update(self._resolved_cache[domain])
        return sorted(all_ips)

    def get_proxy_ips(self):
        """Get IPs that should use proxy"""
        domains = self.config.get("proxy_domains", [])
        return self.get_resolved_ips(domains, refresh=True)

    def get_bypass_ips(self):
        """Get IPs that should bypass proxy"""
        domains = self.config.get("bypass_domains", [])
        return self.get_resolved_ips(domains, refresh=True)

    def generate_iptables_rules(self, proxy_server_ip=None):
        """
        Generate iptables rule commands.
        Returns a list of (cmd, description) tuples.
        """
        mode = self.config.get("proxy_mode", "whitelist")
        port = str(self.config.get("redsocks_port", 12345))
        chain = "IP2FREE_AUTO"
        rules = []

        # Step 1: create and clear the chain.  This order makes first use and
        # a prior `clean` safe, instead of leaving the OUTPUT jump half-set.
        rules.append((
            f"iptables -t nat -N {chain}",
            "确保 IP2FREE_AUTO 链存在",
        ))
        rules.append((
            f"iptables -t nat -F {chain}",
            "清空 IP2FREE_AUTO 链",
        ))

        if not self.config.get("proxy_enabled", False):
            return rules

        # Step 3: Private networks (always bypass)
        for net in self.PRIVATE_NETS:
            rules.append((
                f"iptables -t nat -A {chain} -d {net} -j RETURN",
                f"跳过 {net}",
            ))

        # Step 4: Proxy server IP (avoid loop)
        if proxy_server_ip:
            rules.append((
                f"iptables -t nat -A {chain} -d {proxy_server_ip} -j RETURN",
                f"跳过代理服务器 {proxy_server_ip}",
            ))

        if mode == "blacklist":
            # Bypass domains go first
            bypass_ips = self.get_bypass_ips()
            for ip in bypass_ips:
                rules.append((
                    f"iptables -t nat -A {chain} -d {ip} -j RETURN",
                    f"跳过 (blacklist) {ip}",
                ))

            # Default: redirect all TCP
            rules.append((
                f"iptables -t nat -A {chain} -p tcp -j REDIRECT --to-ports {port}",
                f"重定向 TCP → redsocks:{port}",
            ))

        elif mode == "whitelist":
            proxy_ips = self.get_proxy_ips()
            for ip in proxy_ips:
                rules.append((
                f"iptables -t nat -A {chain} -p tcp -d {ip} -j REDIRECT --to-ports {port}",
                    f"代理 (whitelist) {ip}",
                ))

            # Proxy-specific rules go first; only traffic with no match above bypasses.
            rules.append((
                f"iptables -t nat -A {chain} -j RETURN",
                "默认不代理",
            ))

        # Step 5: Add OUTPUT jump
        rules.append((
            f"iptables -t nat -I OUTPUT 1 -p tcp -j {chain}",
            "添加 OUTPUT 跳转",
        ))

        return rules

    def generate_ip6tables_rules(self, resolved_cache=None):
        """Generate ip6tables rules for blocking IPv6 to specific domains"""
        rules = []
        chain = "IPV6_BLOCK_GOOGLE"

        rules.append((
            f"ip6tables -N {chain}",
            f"确保 {chain} 链存在",
        ))

        rules.append((
            f"ip6tables -F {chain}",
            "清空 IPV6_BLOCK_GOOGLE 链",
        ))

        # Get all resolved IPv6 addresses for bypass and proxy domains
        all_domains = set(
            self.config.get("bypass_domains", []) +
            self.config.get("proxy_domains", []) +
            self.config.get("ipv6_block_domains", [])
        )

        # Resolve each domain for IPv6.  getaddrinfo may return the same
        # address more than once; emitting one DROP per address keeps apply
        # idempotent and makes the rules page truthful.
        ipv6_ips = set()
        for domain in all_domains:
            try:
                infos = socket.getaddrinfo(domain, None, socket.AF_INET6)
                for info in infos:
                    ipv6_ips.add(info[4][0])
            except Exception:
                pass

        for ip in sorted(ipv6_ips):
            rules.append((
                f"ip6tables -A {chain} -d {ip} -j DROP",
                f"屏蔽 IPv6: {ip}",
            ))

        rules.append((
            f"ip6tables -I OUTPUT 1 -j {chain}",
            "添加 OUTPUT 跳转",
        ))

        return rules

    # ---- Config helpers ----

    def set_proxy_enabled(self, enabled):
        self.config["proxy_enabled"] = enabled is True
        self._save_config()

    def set_proxy_mode(self, mode):
        if mode not in {"whitelist", "blacklist"}:
            raise ValueError("proxy_mode 必须是 whitelist 或 blacklist")
        self.config["proxy_mode"] = mode
        self._save_config()

    def add_proxy_domain(self, domain):
        domain = self._normalize_domain(domain)
        domains = self.config.get("proxy_domains", [])
        if domain and domain not in domains:
            domains.append(domain)
            self.config["proxy_domains"] = domains
            self._save_config()
            return True
        return False

    def remove_proxy_domain(self, domain):
        domains = self.config.get("proxy_domains", [])
        if domain in domains:
            domains.remove(domain)
            self.config["proxy_domains"] = domains
            self._save_config()
            return True
        return False

    def add_bypass_domain(self, domain):
        domain = self._normalize_domain(domain)
        domains = self.config.get("bypass_domains", [])
        if domain and domain not in domains:
            domains.append(domain)
            self.config["bypass_domains"] = domains
            self._save_config()
            return True
        return False

    def remove_bypass_domain(self, domain):
        domains = self.config.get("bypass_domains", [])
        if domain in domains:
            domains.remove(domain)
            self.config["bypass_domains"] = domains
            self._save_config()
            return True
        return False

    def set_bypass_domains(self, domains):
        self.config["bypass_domains"] = self._normalize_domains(domains)
        self._save_config()

    def set_proxy_domains(self, domains):
        self.config["proxy_domains"] = self._normalize_domains(domains)
        self._save_config()

    @staticmethod
    def _normalize_domain(domain):
        domain = str(domain or "").strip().lower().rstrip(".")
        if not domain or len(domain) > 253 or not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain
        ):
            raise ValueError("域名格式无效")
        return domain

    @classmethod
    def _normalize_domains(cls, domains):
        if not isinstance(domains, list):
            raise ValueError("域名列表必须是数组")
        # Preserve input order so the saved configuration is stable.
        return list(dict.fromkeys(cls._normalize_domain(domain) for domain in domains))

    def get_status(self):
        """Return current status for dashboard"""
        mode = self.config.get("proxy_mode", "blacklist")
        mode_label = "黑名单模式" if mode == "blacklist" else "白名单模式"

        return {
            "proxy_enabled": self.config.get("proxy_enabled", True),
            "proxy_mode": mode,
            "mode_label": mode_label,
            "proxy_domain_count": len(self.config.get("proxy_domains", [])),
            "bypass_domain_count": len(self.config.get("bypass_domains", [])),
            "ipv6_block_domain_count": len(self.config.get("ipv6_block_domains", [])),
            "proxy_strategy": self.config.get("proxy_strategy", "first"),
            "auto_refresh_enabled": self.config.get("auto_refresh_enabled", True),
            "auto_refresh_times": self.config.get("auto_refresh_times", []),
            "redsocks_port": self.config.get("redsocks_port", 12345),
            "panel_port": self.config.get("panel_port", 8899),
            "https_port": self.config.get("https_port", 8899),
        }

    def get_proxy_state(self):
        """Read proxy_state.json for current proxy info"""
        state_file = DATA_DIR / "proxy_state.json"
        if state_file.exists():
            try:
                return json.loads(state_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, IOError):
                return None
        return None

    def save_proxy_state(self, state):
        """Persist current proxy state so panel flows stay in sync."""
        if state is None:
            state_file = DATA_DIR / "proxy_state.json"
            if state_file.exists():
                state_file.unlink()
            return
        state_file = DATA_DIR / "proxy_state.json"
        state_file.write_text(
            json.dumps(state, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def get_last_resolve_time(self):
        """Return human-readable last resolve time"""
        if self._last_resolve_time > 0:
            return datetime.fromtimestamp(self._last_resolve_time).strftime("%H:%M:%S")
        return "从未"
