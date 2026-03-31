let authToken = localStorage.getItem('client_auth_token') || '';
let isRefreshing = false;

// DOM 元素
const elements = {
    loginContainer: document.getElementById('login-container'),
    dashboardContainer: document.getElementById('dashboard-container'),
    statusBadge: document.getElementById('status-badge'),
    logOutput: document.getElementById('log-output'),
    serverAddr: document.getElementById('server-addr'),
    proxyUser: document.getElementById('proxy-user'),
    proxyPasswd: document.getElementById('proxy-passwd'),
    totpSecret: document.getElementById('totp-secret'),
    forwardList: document.getElementById('forward-list'),
    connList: document.getElementById('conn-list'),
    startBtn: document.getElementById('start-btn'),
    stopBtn: document.getElementById('stop-btn'),
    loginBtn: document.getElementById('login-btn'),
    password: document.getElementById('password'),
    loginError: document.getElementById('login-error')
};

// 初始化
init();

function init() {
    if (authToken) {
        checkAuth();
    } else {
        showLogin();
    }
    setupEventListeners();
}

async function checkAuth() {
    try {
        const res = await fetch('/api/status', {
            headers: { 'Authorization': authToken }
        });
        if (res.status === 401) {
            showLogin();
        } else {
            const data = await res.json();
            showDashboard(data);
        }
    } catch (e) {
        showLogin();
    }
}

function showLogin() {
    elements.loginContainer.style.display = 'block';
    elements.dashboardContainer.style.display = 'none';
}

function showDashboard(data) {
    elements.loginContainer.style.display = 'none';
    elements.dashboardContainer.style.display = 'block';
    
    // 首次加载填充配置
    if (data.config) {
        elements.serverAddr.value = data.config.SERVER_ADDR || '';
        elements.proxyUser.value = data.config.PROXY_USER || '';
        elements.proxyPasswd.value = data.config.PROXY_PASSWD || '';
        elements.totpSecret.value = data.config.TOTP_SECRET_KEY || '';
    }
    
    updateUI(data);
    
    if (!window.statusTimer) {
        window.statusTimer = setInterval(refreshStatus, 2000);
    }
}

async function refreshStatus() {
    if (isRefreshing) return;
    isRefreshing = true;
    try {
        const res = await fetch('/api/status', {
            headers: { 'Authorization': authToken }
        });
        if (res.status === 401) {
            clearInterval(window.statusTimer);
            showLogin();
            return;
        }
        const data = await res.json();
        updateUI(data);
    } catch (e) {
        console.error("Refresh failed", e);
    } finally {
        isRefreshing = false;
    }
}

function updateUI(data) {
    // 状态更新
    if (data.is_running) {
        elements.statusBadge.textContent = '运行中';
        elements.statusBadge.className = 'badge running';
        elements.startBtn.style.display = 'none';
        elements.stopBtn.style.display = 'inline-block';
    } else {
        elements.statusBadge.textContent = '已断开';
        elements.statusBadge.className = 'badge disconnected';
        elements.startBtn.style.display = 'inline-block';
        elements.stopBtn.style.display = 'none';
    }

    // 规则更新
    renderForwards(data.state.Forwards || []);
    
    // 连接更新
    renderConnections(data.state.active_conns || {});
}

function renderForwards(forwards) {
    elements.forwardList.innerHTML = '';
    if (forwards.length === 0) {
        elements.forwardList.innerHTML = '<div class="muted">暂无转发规则，连接后将从服务器同步</div>';
        return;
    }
    forwards.forEach(f => {
        const div = document.createElement('div');
        div.className = 'rule-item';
        div.innerHTML = `
            <div class="port-box">${f.REMOTE_PORT || '随机'}</div>
            <div class="arrow">➔</div>
            <div class="target-addr">${f.LOCAL_ADDR}</div>
        `;
        elements.forwardList.appendChild(div);
    });
}

function renderConnections(conns) {
    elements.connList.innerHTML = '';
    const keys = Object.keys(conns);
    if (keys.length === 0) {
        elements.connList.innerHTML = '<tr><td colspan="4" class="muted" style="text-align:center">当前无活跃连接</td></tr>';
        return;
    }
    
    keys.forEach(id => {
        const c = conns[id];
        const row = document.createElement('tr');
        const duration = Math.floor((Date.now() - new Date(c.connected_at).getTime()) / 1000);
        row.innerHTML = `
            <td><code>${c.id.substring(0,8)}</code></td>
            <td><span class="port-box">${c.remote_port}</span></td>
            <td>${c.local_addr}</td>
            <td>${duration}s</td>
        `;
        elements.connList.appendChild(row);
    });
}

function setupEventListeners() {
    elements.loginBtn.onclick = async () => {
        const pass = elements.password.value;
        const res = await fetch('/api/login', {
            method: 'POST',
            body: JSON.stringify({ password: pass })
        });
        if (res.ok) {
            const data = await res.json();
            authToken = data.token;
            localStorage.setItem('client_auth_token', authToken);
            checkAuth();
        } else {
            elements.loginError.textContent = '认证失败，请检查密码或 Token';
        }
    };

    elements.startBtn.onclick = async () => {
        const config = {
            SERVER_ADDR: elements.serverAddr.value,
            PROXY_USER: elements.proxyUser.value,
            PROXY_PASSWD: elements.proxyPasswd.value,
            TOTP_SECRET_KEY: elements.totpSecret.value
        };

        addLog('正在尝试连接服务器...');
        const res = await fetch('/api/start', {
            method: 'POST',
            headers: { 
                'Authorization': authToken,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ config })
        });

        if (res.ok) {
            addLog('启动指令已成功下达');
            refreshStatus();
        } else {
            addLog('启动失败: ' + await res.text());
        }
    };

    elements.stopBtn.onclick = async () => {
        const res = await fetch('/api/stop', {
            method: 'POST',
            headers: { 'Authorization': authToken }
        });
        if (res.ok) {
            addLog('正在停止服务...');
            refreshStatus();
        }
    };
}

function addLog(msg) {
    const time = new Date().toLocaleTimeString();
    const div = document.createElement('div');
    div.innerHTML = `<span class="time">${time}</span> ${msg}`;
    elements.logOutput.appendChild(div);
    elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
}
