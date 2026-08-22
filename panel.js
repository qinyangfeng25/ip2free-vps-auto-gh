(function () {
    window.panel = {};
    const panel = window.panel;
    let currentStatus = null;

    function $(id) {
        return document.getElementById(id);
    }

    panel.toast = function (msg, type) {
        let box = $('toast-container');
        if (!box) {
            box = document.createElement('div');
            box.id = 'toast-container';
            box.className = 'toast-container';
            document.body.appendChild(box);
        }
        const el = document.createElement('div');
        el.className = 'toast' + (type ? ' ' + type : '');
        el.textContent = msg;
        box.appendChild(el);
        setTimeout(function () {
            el.remove();
        }, 3800);
    };

    panel.api = async function (path, options) {
        options = options || {};
        options.headers = options.headers || {};
        if (options.body && !options.headers['Content-Type']) {
            options.headers['Content-Type'] = 'application/json';
        }
        const resp = await fetch(path, {
            method: options.method || 'GET',
            headers: options.headers,
            body: options.body ? JSON.stringify(options.body) : undefined,
            credentials: 'same-origin'
        });
        let data = {};
        try {
            data = await resp.json();
        } catch (e) {
            data = {};
        }
        if (!resp.ok) {
            throw new Error(data.error || data.msg || ('HTTP ' + resp.status));
        }
        return data;
    };

    function setBtn(btn, loadingText) {
        if (!btn) return;
        if (btn.dataset.origHtml) {
            btn.innerHTML = btn.dataset.origHtml;
            btn.disabled = false;
            delete btn.dataset.origHtml;
            return;
        }
        btn.dataset.origHtml = btn.innerHTML;
        btn.innerHTML = '<span>' + (loadingText || '处理中...') + '</span>';
        btn.disabled = true;
    }

    function wrap(asyncFn) {
        return async function () {
            const btn = event && event.currentTarget ? event.currentTarget : null;
            if (btn) setBtn(btn, btn.dataset.loading || '处理中...');
            try {
                await asyncFn.apply(this, arguments);
            } catch (e) {
                panel.toast(String(e.message || e), 'error');
            } finally {
                if (btn) setBtn(btn);
            }
        };
    }

    function safeText(value, fallback) {
        return value === undefined || value === null || value === '' ? (fallback || '-') : String(value);
    }

    panel.loadStatus = async function (silent) {
        try {
            const data = await panel.api('/api/status');
            currentStatus = data;
            const modeLabel = data.mode_label || (data.proxy_mode === 'whitelist' ? '白名单模式' : '黑名单模式');
            const enabled = data.proxy_enabled === true ? '运行中' : '已关闭';
            if ($('live-status')) {
                const textEl = $('live-status .text');
                if (textEl) textEl.textContent = enabled;
            }
            if ($('stat-proxy-status')) $('stat-proxy-status').textContent = enabled;
            if ($('stat-exit-ip')) $('stat-exit-ip').textContent = safeText(data.exit_ip, '--');
            if ($('stat-domain-count')) {
                const cnt = (data.proxy_domain_count || 0) + (data.bypass_domain_count || 0);
                $('stat-domain-count').textContent = String(cnt);
            }
            if ($('stat-next-refresh')) {
                const times = data.auto_refresh_times || [];
                $('stat-next-refresh').textContent = times.length ? times.join(' / ') : '未设置';
            }
            if ($('stat-mode')) $('stat-mode').textContent = modeLabel;
            if ($('stat-proxy-count')) $('stat-proxy-count').textContent = safeText(data.proxy_domain_count, '-');
            if ($('stat-bypass-count')) $('stat-bypass-count').textContent = safeText(data.bypass_domain_count, '-');
            if ($('toggle-proxy-btn')) {
                const t = $('toggle-proxy-text');
                if (t) {
                    t.textContent = data.proxy_enabled ? '关闭代理' : '开启代理';
                }
            }
            const proxy = data.proxy_state || {};
            if ($('stat-current-ip')) $('stat-current-ip').textContent = safeText(proxy.ip, '--');
            if ($('stat-source')) $('stat-source').textContent = safeText(proxy.source, '--');
            if ($('stat-loc')) $('stat-loc').textContent = safeText(proxy.country, '--') + ' ' + safeText(proxy.city, '');
            if ($('stat-proto')) $('stat-proto').textContent = safeText(proxy.protocol, '--');
            if ($('proxy-detail')) {
                renderProxyDetail($('proxy-detail'), proxy, data.exit_ip);
            }
            if ($('service-status')) {
                renderProxyDetail($('service-status'), {
                    ip: '状态读取',
                    port: 'Nginx',
                    username: 'HTTP 面板',
                    source: 'HTTP ' + safeText(data.panel_port || '--'),
                    country: 'HTTPS 反代',
                    city: 'HTTPS ' + safeText(data.https_port || '--')
                }, (data.nginx && data.nginx.active) ? '运行中' : '未运行');
            }
            if ($('https-hint')) {
                const nginx = data.nginx || {};
                const rows = [
                    ['Nginx 状态', nginx.active ? '运行中' : '未运行'],
                    ['Nginx 配置', nginx.config_valid ? '有效' : ('异常：' + (nginx.test_output || '').split('\n').pop().slice(-80))],
                    ['SSL 证书', nginx.ssl_cert_exists && nginx.ssl_key_exists ? '已就绪' : '缺失'],
                    ['访问地址', nginx.config_valid ? 'https://92.118.228.210:' + safeText(data.https_port || 8899) : '请先修复 Nginx 配置']
                ];
                renderProxyDetail($('https-hint'), {
                    ip: rows[0][1],
                    port: rows[1][1],
                    username: rows[2][1],
                    source: rows[3][1],
                    country: '',
                    city: ''
                }, 'HTTPS');
            }
        } catch (e) {
            if (!silent) panel.toast(String(e.message || e), 'error');
            if ($('live-status .text')) {
                const textEl = $('live-status .text');
                if (textEl) textEl.textContent = '状态读取失败';
            }
        }
    };

    function renderProxyDetail(box, proxy, exitIp) {
        box.innerHTML = '';
        const rows = [
            ['代理 IP', safeText(proxy.ip)],
            ['端口', safeText(proxy.port)],
            ['账号', safeText(proxy.username)],
            ['来源', safeText(proxy.source)],
            ['地区', safeText(proxy.country) + ' ' + safeText(proxy.city, '')],
            ['系统出口', safeText(exitIp)]
        ];
        rows.forEach(function (item) {
            const div = document.createElement('div');
            div.className = 'row';
            const label = document.createElement('span');
            label.className = 'label';
            label.textContent = item[0];
            const value = document.createElement('span');
            value.className = 'value';
            value.textContent = item[1];
            div.appendChild(label);
            div.appendChild(value);
            box.appendChild(div);
        });
    }

    panel.refreshProxy = wrap(async function () {
        const data = await panel.api('/api/refresh', {method: 'POST', body: {}});
        panel.toast(data.ok ? '代理刷新成功' : '代理刷新失败', data.ok ? 'success' : 'error');
        if (data.output) {
            panel.toast(data.output.split('\n').pop(), data.ok ? 'success' : 'error');
        }
        panel.loadStatus(true);
    });

    panel.applyRules = wrap(async function () {
        const data = await panel.api('/api/apply-rules', {method: 'POST', body: {}});
        let msg = '规则已应用';
        if (data.redsocks === false) msg = '规则已应用，但 redsocks 重启异常';
        panel.toast(msg, 'success');
        panel.loadStatus(true);
        return data;
    });

    panel.detectAll = wrap(async function () {
        const data = await panel.api('/api/proxy-detect-all', {
            method: 'POST', body: {limit: 2, concurrency: 2}
        });
        panel.toast('检测完成：可用 ' + (data.available || 0) + '，纯净 ' + (data.pure || 0) + '，共 ' + (data.total || 0) + ' 个 IP', 'success');
        proxyCache = data.results || [];
        renderProxyResults(data.results || []);
    });

    panel.toggleProxy = wrap(async function () {
        const enabled = !(currentStatus && currentStatus.proxy_enabled);
        const data = await panel.api('/api/proxy-enable', {method: 'POST', body: {enabled: enabled}});
        panel.toast(enabled ? '代理已开启' : '代理已关闭', 'success');
        panel.loadStatus(true);
    });

    panel.logout = async function () {
        try {
            await panel.api('/api/logout', {method: 'POST', body: {}});
        } catch (e) {}
        location.href = '/login';
    };

    panel.init = function () {
        const logoutBtn = document.querySelector('.sidebar-footer button');
        if (logoutBtn) logoutBtn.addEventListener('click', panel.logout);
    };

    // ==================== Domains ====================

    panel.initDomains = function () {
        loadDomainConfig();
        updateResolved();
        setInterval(function () {
            updateResolved(true);
        }, 15000);
    };

    async function loadDomainConfig() {
        try {
            const cfg = await panel.api('/api/config');
            const mode = cfg.proxy_mode || 'blacklist';
            document.querySelectorAll('.segment').forEach(function (s) {
                s.classList.toggle('active', s.dataset.mode === mode);
            });
            renderTags('proxy', cfg.proxy_domains || []);
            renderTags('bypass', cfg.bypass_domains || []);
            const s = await panel.api('/api/status');
            if ($('stat-proxy-count')) $('stat-proxy-count').textContent = String((cfg.proxy_domains || []).length);
            if ($('stat-bypass-count')) $('stat-bypass-count').textContent = String((cfg.bypass_domains || []).length);
            if ($('stat-mode')) $('stat-mode').textContent = mode === 'whitelist' ? '白名单模式' : '黑名单模式';
            if ($('stat-resolved-count')) $('stat-resolved-count').textContent = safeText(s.proxy_domain_count + s.bypass_domain_count, '0');
        } catch (e) {
            panel.toast(String(e.message || e), 'error');
        }
    }

    function renderTags(type, list) {
        const box = $(type + '-domain-tags');
        const empty = $(type + '-domain-empty');
        if (!box) return;
        box.innerHTML = '';
        if (empty) empty.style.display = list.length ? 'none' : '';
        list.forEach(function (domain) {
            const tag = document.createElement('span');
            tag.className = 'tag';
            const span = document.createElement('span');
            span.textContent = domain;
            const btn = document.createElement('button');
            btn.innerHTML = '&times;';
            btn.title = '移除';
            btn.addEventListener('click', function () {
                removeDomain(type, domain);
            });
            tag.appendChild(span);
            tag.appendChild(btn);
            box.appendChild(tag);
        });
    }

    panel.addDomain = wrap(async function (type) {
        const input = $(type + '-domain-input');
        const domain = input.value.trim();
        if (!domain) {
            panel.toast('请输入域名', 'error');
            return;
        }
        await panel.api('/api/domains/' + type, {method: 'POST', body: {domain: domain}});
        input.value = '';
        panel.toast('已添加域名', 'success');
        loadDomainConfig();
        updateResolved();
    });

    async function removeDomain(type, domain) {
        try {
            await panel.api('/api/domains/' + type, {method: 'DELETE', body: {domain: domain}});
            panel.toast('已移除域名', 'success');
            loadDomainConfig();
            updateResolved();
        } catch (e) {
            panel.toast(String(e.message || e), 'error');
        }
    }

    panel.setMode = wrap(async function (mode) {
        await panel.api('/api/proxy-mode', {method: 'POST', body: {mode: mode}});
        document.querySelectorAll('.segment').forEach(function (s) {
            s.classList.toggle('active', s.dataset.mode === mode);
        });
        panel.toast(mode === 'whitelist' ? '已切换为白名单模式' : '已切换为黑名单模式', 'success');
        loadDomainConfig();
    });

    panel.resolveNow = wrap(async function () {
        await panel.applyRules();
        updateResolved();
    });

    async function updateResolved(silent) {
        const box = $('resolved-output');
        if (!box) return;
        try {
            const data = await panel.api('/api/resolved-ips');
            const lines = [];
            lines.push('模式: ' + (data.mode === 'whitelist' ? '白名单' : '黑名单'));
            lines.push('代理 IP: ' + (data.proxy_ips.length ? data.proxy_ips.join(' ') : '无'));
            lines.push('绕过 IP: ' + (data.bypass_ips.length ? data.bypass_ips.join(' ') : '无'));
            box.textContent = lines.join('\n');
            if ($('stat-resolved-count')) $('stat-resolved-count').textContent = String(data.proxy_ips.length + data.bypass_ips.length);
        } catch (e) {
            if (!silent) {
                box.textContent = '解析失败: ' + e.message;
            }
        }
    }

    // ==================== Proxies ====================

    let proxyCache = [];

    panel.initProxies = function () {
        panel.loadStatus(true);
        loadProxyList();
        const tb = $('proxy-table-body');
        if (tb) {
            tb.addEventListener('click', function (e) {
                const btn = e.target.closest('[data-switch]');
                if (!btn) return;
                const idx = Number(btn.dataset.switch);
                const p = proxyCache[idx];
                if (p) switchProxy(p);
            });
        }
    };

    panel.loadProxyList = wrap(async function () {
        await loadProxyList();
        panel.toast('代理列表已加载', 'success');
    });

    async function loadProxyList() {
        const data = await panel.api('/api/proxy-list');
        proxyCache = data.proxies || [];
        renderProxyTable(proxyCache);
        const activeProxy = proxyCache.find(function (p) {
            return p && p.is_active;
        });
        if ($('stat-current-ip') && activeProxy) {
            $('stat-current-ip').textContent = activeProxy.ip;
            $('stat-source').textContent = safeText(activeProxy.source);
            $('stat-loc').textContent = safeText(activeProxy.country) + ' ' + safeText(activeProxy.city, '');
            $('stat-proto').textContent = safeText(activeProxy.protocol);
        }
        const note = $('proxy-loading-note');
        if (note) note.textContent = '当前缓存 ' + proxyCache.length + ' 个代理';
    }

    function renderProxyTable(proxies) {
        const tb = $('proxy-table-body');
        if (!tb) return;
        tb.innerHTML = '';
        if (!proxies.length) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.setAttribute('colspan', '7');
            td.className = 'table-empty';
            td.textContent = '暂无代理数据';
            tr.appendChild(td);
            tb.appendChild(tr);
            return;
        }
        proxies.forEach(function (p, i) {
            const tr = document.createElement('tr');
            const cells = [
                [p.ip, 'mono'],
                [safeText(p.port), ''],
                [safeText(p.protocol), ''],
                [safeText(p.country) + ' ' + safeText(p.city, ''), ''],
                [safeText(p.source), '']
            ];
            cells.forEach(function (c) {
                const td = document.createElement('td');
                if (c[1]) td.className = 'mono';
                td.textContent = c[0];
                tr.appendChild(td);
            });
            const typeTd = document.createElement('td');
            if (p.detected) {
                typeTd.appendChild(renderTypeBadge(p.detected));
            } else {
                typeTd.textContent = '未检测';
            }
            tr.appendChild(typeTd);
            const actTd = document.createElement('td');
            const switchBtn = document.createElement('button');
            switchBtn.className = 'btn btn-sm btn-primary';
            switchBtn.textContent = '切换';
            switchBtn.dataset.switch = String(i);
            if (p.is_active) {
                switchBtn.disabled = true;
                switchBtn.textContent = '当前';
            }
            actTd.appendChild(switchBtn);
            tr.appendChild(actTd);
            tb.appendChild(tr);
        });
    }

    function renderProxyResults(results) {
        const tb = $('proxy-table-body');
        if (!tb) return;
        tb.innerHTML = '';
        if (!results.length) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.setAttribute('colspan', '7');
            td.className = 'table-empty';
            td.textContent = '没有解析到代理列表';
            tr.appendChild(td);
            tb.appendChild(tr);
            return;
        }
        results.forEach(function (r, idx) {
            const tr = document.createElement('tr');
            const tdIp = document.createElement('td');
            tdIp.className = 'mono';
            tdIp.textContent = r.ip;
            tr.appendChild(tdIp);
            const tdPort = document.createElement('td');
            tdPort.textContent = safeText(r.port, '-');
            tr.appendChild(tdPort);
            const tdProto = document.createElement('td');
            tdProto.textContent = safeText(r.protocol, '-');
            tr.appendChild(tdProto);
            const tdExitIp = document.createElement('td');
            tdExitIp.className = 'mono';
            const availability = r.availability || {};
            tdExitIp.textContent = availability.available ? (availability.detected_ip || r.ip) : '-';
            tr.appendChild(tdExitIp);
            const tdAvail = document.createElement('td');
            if (availability.available) {
                const span = document.createElement('span');
                span.className = 'tag';
                span.style.background = 'rgba(34,197,94,.14)';
                span.style.color = 'var(--green)';
                span.textContent = '可用 ' + availability.latency_ms + 'ms';
                tdAvail.appendChild(span);
            } else {
                const span = document.createElement('span');
                span.className = 'tag';
                span.style.background = 'rgba(239,68,68,.14)';
                span.style.color = 'var(--red)';
                span.textContent = '不可用';
                tdAvail.appendChild(span);
                if (availability.error) tdAvail.title = availability.error;
            }
            tr.appendChild(tdAvail);
            const tdPurity = document.createElement('td');
            tdPurity.appendChild(renderTypeBadge(r.detected));
            tr.appendChild(tdPurity);
            const tdAct = document.createElement('td');
            if (r.is_active) {
                tdAct.textContent = '当前';
            } else {
                const btn = document.createElement('button');
                btn.className = 'btn btn-sm btn-primary';
                btn.textContent = '切换';
                btn.addEventListener('click', function () { switchProxy(r); });
                tdAct.appendChild(btn);
            }
            tr.appendChild(tdAct);
            tb.appendChild(tr);
        });
    }

    function renderTypeBadge(detected) {
        const span = document.createElement('span');
        span.className = 'tag';
        if (detected) {
            span.textContent = detected.type + ' ' + detected.score + '/100';
            span.title = detected.details || detected.confidence;
            if (detected.type === 'residential') {
                span.style.background = 'rgba(34,197,94,.14)';
                span.style.color = 'var(--green)';
            } else if (detected.type === 'datacenter') {
                span.style.background = 'rgba(248,113,113,.14)';
                span.style.color = 'var(--orange)';
            }
        } else {
            span.textContent = '未知';
        }
        return span;
    }

    async function switchProxy(p) {
        try {
            panel.toast('正在切换代理，可能需要几秒...');
            const data = await panel.api('/api/proxy-switch', {
                method: 'POST',
                body: {
                    ip: p.ip,
                    port: p.port,
                    protocol: p.protocol,
                    username: p.username,
                    password: p.password
                }
            });
            panel.toast(data.verified ? '切换成功，代理出口已验证' : (data.verification_note || '代理配置已应用，尚未验证出口'), data.verified ? 'success' : 'warning');
            panel.loadStatus(true);
            await loadProxyList();
        } catch (e) {
            panel.toast(String(e.message || e), 'error');
        }
    }

    // ==================== Iptables ====================

    panel.initIptables = function () {
        loadIptables();
        loadRedsocks();
    };

    panel.loadIptables = wrap(async function () {
        await Promise.all([loadIptables, loadRedsocks].map(fn => fn()));
    });

    async function loadIptables() {
        const data = await panel.api('/api/iptables');
        if ($('iptables-output')) $('iptables-output').textContent = data.iptables || '无规则';
        if ($('ip6tables-output')) $('ip6tables-output').textContent = data.ip6tables || '无规则';
        if ($('iptables-status')) $('iptables-status').textContent = data.iptables && data.iptables !== '无规则' ? '已生效' : '未应用';
        if ($('ip6tables-status')) $('ip6tables-status').textContent = data.ip6tables && data.ip6tables !== '无规则' ? '已生效' : '未应用';
    }

    async function loadRedsocks() {
        const data = await panel.api('/api/redsocks-config');
        if ($('redsocks-output')) $('redsocks-output').textContent = data.config || '暂无配置';
    }

    // ==================== Logs ====================

    let logsCache = [];

    panel.initLogs = function () {
        loadLogs();
    };

    panel.loadLogs = wrap(async function () {
        await loadLogs();
    });

    async function loadLogs() {
        const data = await panel.api('/api/logs');
        logsCache = data.logs || [];
        renderLogs(logsCache);
    }

    panel.filterLogs = function () {
        const q = $('log-filter') ? $('log-filter').value.trim().toLowerCase() : '';
        if (!q) {
            renderLogs(logsCache);
            return;
        }
        renderLogs(logsCache.filter(function (line) {
            return String(line).toLowerCase().indexOf(q) >= 0;
        }));
    };

    function renderLogs(lines) {
        const box = $('logs-view');
        if (!box) return;
        box.innerHTML = '';
        if (!lines.length) {
            box.textContent = '暂无日志';
            return;
        }
        lines.forEach(function (line) {
            const div = document.createElement('div');
            div.className = 'log-line';
            div.textContent = line;
            box.appendChild(div);
        });
    }

    // ==================== Settings ====================

    panel.initSettings = function () {
        loadSettings();
    };

    panel.loadSettings = wrap(async function () {
        await loadSettings();
    });

    async function loadSettings() {
        const cfg = await panel.api('/api/config');
        const set = function (id, val) {
            const el = $(id);
            if (el) el.value = val === undefined || val === null ? '' : String(val);
        };
        set('proxy_source', cfg.proxy_source || 'both');
        set('proxy_strategy', cfg.proxy_strategy || 'first');
        set('country_filter', cfg.country_filter || '');
        set('city_filter', cfg.city_filter || '');
        set('max_retries', cfg.max_retries || 5);
        set('auto_refresh_times', (cfg.auto_refresh_times || ['09:00', '15:00', '20:00']).join(','));
        set('proxy_mode', cfg.proxy_mode || 'blacklist');
        set('dns_ttl_seconds', cfg.dns_ttl_seconds || 300);
        set('panel_port', cfg.panel_port || 8889);
        set('https_port', cfg.https_port || 8899);
        set('panel_username', cfg.panel_username || 'admin');
        set('panel_password', cfg.panel_password || '');
    }

    panel.saveSettings = wrap(async function () {
        const val = function (id, fallback) {
            const el = $(id);
            if (!el) return fallback;
            return el.value.trim();
        };
        const cfg = {
            proxy_source: val('proxy_source', 'both'),
            proxy_strategy: val('proxy_strategy', 'first'),
            country_filter: val('country_filter', ''),
            city_filter: val('city_filter', ''),
            max_retries: Number(val('max_retries', 5)),
            auto_refresh_times: val('auto_refresh_times', '09:00,15:00,20:00').split(',').map(function (s) { return s.trim(); }).filter(Boolean),
            proxy_mode: val('proxy_mode', 'blacklist'),
            dns_ttl_seconds: Number(val('dns_ttl_seconds', 300)),
            panel_port: Number(val('panel_port', 8889)),
            https_port: Number(val('https_port', 8899)),
            panel_username: val('panel_username', 'admin'),
            panel_password: val('panel_password', '')
        };
        await panel.api('/api/config', {method: 'POST', body: cfg});
        panel.toast('设置已保存', 'success');
        if (cfg.proxy_mode) {
            await panel.api('/api/proxy-mode', {method: 'POST', body: {mode: cfg.proxy_mode}});
        }
        panel.loadStatus(true);
    });
})();
