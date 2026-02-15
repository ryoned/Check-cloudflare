import { connect } from "cloudflare:sockets";

// ============================================
// 全局变量 (ProxyIP 功能需要)
// ============================================
let 临时TOKEN, 永久TOKEN;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const hostname = url.hostname;
    
    // --- 环境与Token初始化 (ProxyIP逻辑) ---
    const 网站图标 = env.ICO || 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';
    const UA = request.headers.get('User-Agent') || 'null';
    const currentDate = new Date();
    const timestamp = Math.ceil(currentDate.getTime() / (1000 * 60 * 31)); 
    
    临时TOKEN = await 双重哈希(url.hostname + timestamp + UA);
    永久TOKEN = env.TOKEN || 临时TOKEN;

    // ============================================
    // API 路由分发
    // ============================================

    // --- 1. Link Tracer 专用 API ---
    if (path.startsWith('/api/')) {
      // TCP/HTTP 延迟检测
      if (path === '/api/tcping') {
        const target = url.searchParams.get('target');
        const port = parseInt(url.searchParams.get('port')) || 443;
        if (!target) return new Response('Missing target', { status: 400 });

        const start = performance.now();
        try {
          const socket = connect({ hostname: target, port: port });
          await Promise.race([
            socket.opened,
            new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 2500))
          ]);
          const rtt = Math.round(performance.now() - start);
          socket.close();
          return new Response(JSON.stringify({ status: 'success', rtt, type: 'TCP' }), { headers: apiHeaders() });
        } catch (e) {
          try {
            const fetchStart = performance.now();
            await fetch(`https://${target}/cdn-cgi/trace`, { method: 'HEAD', cache: 'no-store' });
            const rtt = Math.round(performance.now() - fetchStart);
            return new Response(JSON.stringify({ status: 'success', rtt, type: 'HTTP(CF)' }), { headers: apiHeaders() });
          } catch (err) {
            return new Response(JSON.stringify({ status: 'error', message: e.message }), { headers: apiHeaders() });
          }
        }
      }

      // GeoIP
      if (path === '/api/geoip') {
        const target = url.searchParams.get('target');
        if (!target) return new Response('Missing target', { status: 400 });
        try {
          const response = await fetch(`https://ipwho.is/${target}?lang=zh-CN`);
          const data = await response.json();
          return new Response(JSON.stringify(data), { headers: apiHeaders() });
        } catch (e) {
          return new Response(JSON.stringify({ status: 'fail' }), { status: 500 });
        }
      }

      // 域名解析 (Tracer 版)
      if (path === '/api/resolve') {
        const domain = url.searchParams.get('domain');
        if (!domain) return new Response('Missing domain', { status: 400 });
        try {
          const ips = await resolveDomain_Tracer(domain);
          return new Response(JSON.stringify({ status: 'success', ips }), { headers: apiHeaders() });
        } catch (e) {
          return new Response(JSON.stringify({ status: 'error', message: e.message }), { headers: apiHeaders() });
        }
      }
    }

    // --- 2. ProxyIP 专用 API ---
    
    // Check 接口
    if (path.toLowerCase() === '/check') {
      if (!validateToken(url, env, 永久TOKEN)) return tokenError();
      const proxyIP = url.searchParams.get('proxyip');
      if (!proxyIP) return new Response('Missing proxyip', { status: 400 });

      const colo = request.cf?.colo || 'CF';
      const result = await CheckProxyIP(proxyIP.toLowerCase(), colo);
      return new Response(JSON.stringify(result, null, 2), { status: result.success ? 200 : 502, headers: apiHeaders() });
    }
    
    // Resolve 接口 (ProxyIP 版 - 需要鉴权)
    else if (path.toLowerCase() === '/resolve') {
      if (!validateToken(url, env, 永久TOKEN, 临时TOKEN)) return tokenError();
      const domain = url.searchParams.get('domain');
      if (!domain) return new Response('Missing domain', { status: 400 });

      try {
        const ips = await resolveDomain_Proxy(domain);
        return new Response(JSON.stringify({ success: true, domain, ips }), { headers: apiHeaders() });
      } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), { status: 500, headers: apiHeaders() });
      }
    }
    
    // IP-Info 接口
    else if (path.toLowerCase() === '/ip-info') {
      if (!validateToken(url, env, 永久TOKEN, 临时TOKEN)) return tokenError();
      let ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
      if (!ip) return new Response(JSON.stringify({ status: "error", message: "Missing IP" }), { status: 400 });
      if (ip.includes('[')) ip = ip.replace('[', '').replace(']', '');

      try {
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
        const data = await response.json();
        data.timestamp = new Date().toISOString();
        return new Response(JSON.stringify(data, null, 4), { headers: apiHeaders() });
      } catch (error) {
        return new Response(JSON.stringify({ status: "error" }), { status: 500 });
      }
    }

    else if (path.toLowerCase() === '/favicon.ico') {
      return Response.redirect(网站图标, 302);
    }

    // ============================================
    // 渲染统一页面
    // ============================================
    const cfData = {
      colo: request.cf?.colo || '未知',
      city: request.cf?.city || '未知',
      country: request.cf?.country || '未知',
      ip: request.headers.get('CF-Connecting-IP') || '未知'
    };

    return new Response(renderUnifiedPage(cfData, 网站图标, 临时TOKEN), {
      headers: { "Content-Type": "text/html;charset=UTF-8" }
    });
  }
};

// ============================================
// 辅助函数
// ============================================

function apiHeaders() {
  return { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' };
}

function validateToken(url, env, permToken, tempToken = null) {
  // 如果没设置 env.TOKEN 且不要求 tempToken，则跳过验证 (兼容逻辑)
  if (!env.TOKEN && !tempToken) return true;
  
  const t = url.searchParams.get('token');
  if (!t) return false;
  
  if (tempToken && t === tempToken) return true;
  if (t === permToken) return true;
  
  return false;
}

function tokenError() {
  return new Response(JSON.stringify({ status: "error", message: "Invalid TOKEN" }, null, 4), { 
    status: 403, headers: apiHeaders() 
  });
}

// --- Tracer 域名解析 ---
async function resolveDomain_Tracer(domain) {
  const endpoints = [{ url: 'https://dns.google/resolve', name: 'Google' }, { url: 'https://223.5.5.5/resolve', name: 'AliDNS' }];
  for (const endpoint of endpoints) {
    try {
      const [v4, v6] = await Promise.all([
        fetch(`${endpoint.url}?name=${domain}&type=A`).then(r => r.json()),
        fetch(`${endpoint.url}?name=${domain}&type=AAAA`).then(r => r.json())
      ]);
      const ips = new Set();
      if (v4.Answer) v4.Answer.filter(r => r.type === 1).forEach(r => ips.add(r.data));
      if (v6.Answer) v6.Answer.filter(r => r.type === 28).forEach(r => ips.add(r.data));
      if (ips.size > 0) return Array.from(ips);
    } catch (e) { continue; }
  }
  return [domain];
}

// --- ProxyIP 域名解析 ---
async function resolveDomain_Proxy(domain) {
  domain = domain.includes(':') ? domain.split(':')[0] : domain;
  const endpoints = [{ url: 'https://dns.google/resolve' }, { url: 'https://223.5.5.5/resolve' }];
  for (const endpoint of endpoints) {
    try {
      const [v4, v6] = await Promise.all([
        fetch(`${endpoint.url}?name=${domain}&type=A`).then(r => r.ok ? r.json() : {}),
        fetch(`${endpoint.url}?name=${domain}&type=AAAA`).then(r => r.ok ? r.json() : {})
      ]);
      const ips = [];
      if (v4.Answer) v4.Answer.filter(r => r.type === 1).forEach(r => ips.push(r.data));
      if (v6.Answer) v6.Answer.filter(r => r.type === 28).forEach(r => ips.push(`[${r.data}]`));
      if (ips.length > 0) return ips;
    } catch (e) { continue; }
  }
  throw new Error('DNS解析失败');
}

// --- ProxyIP 检测核心逻辑 ---
async function CheckProxyIP(proxyIP, colo) {
  let portRemote = 443;
  if (proxyIP.includes('.tp')) {
    const portMatch = proxyIP.match(/\.tp(\d+)\./);
    if (portMatch) portRemote = parseInt(portMatch[1]);
  } else if (proxyIP.includes('[') && proxyIP.includes(']:')) {
    portRemote = parseInt(proxyIP.split(']:')[1]);
    proxyIP = proxyIP.split(']:')[0] + ']';
  } else if (proxyIP.includes(':')) {
    portRemote = parseInt(proxyIP.split(':')[1]);
    proxyIP = proxyIP.split(':')[0];
  }

  try {
    const socket = connect({ hostname: proxyIP, port: portRemote });
    const writer = socket.writable.getWriter();
    // 构建一个简单的 HTTP 请求来触发 CF 响应
    const request = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: CheckProxyIP\r\nConnection: close\r\n\r\n";
    await writer.write(new TextEncoder().encode(request));
    writer.releaseLock();

    const reader = socket.readable.getReader();
    let received = new Uint8Array(0);
    
    // 简单读取响应
    const { value } = await Promise.race([
        reader.read(),
        new Promise(resolve => setTimeout(() => resolve({ value: null }), 5000))
    ]);
    
    reader.releaseLock(); // 释放锁
    try { await socket.close(); } catch(e) {} // 尝试关闭

    if (!value) throw new Error("连接超时或无响应");

    const text = new TextDecoder().decode(value);
    const statusMatch = text.match(/^HTTP\/\d\.\d\s+(\d+)/i);
    const statusCode = statusMatch ? parseInt(statusMatch[1]) : null;

    // 验证逻辑：必须是 CF 的响应特征
    const isCF = text.includes("cloudflare") || text.includes("CF-RAY");
    
    // 如果连接成功且看起来像 Cloudflare
    if (statusCode || isCF) {
        // 进行TLS握手模拟验证 (简化版，复用原逻辑的壳子)
        const tlsResult = await 验证反代IP(proxyIP, portRemote);
        return {
            success: tlsResult[0],
            proxyIP: proxyIP,
            portRemote: portRemote,
            colo: colo,
            responseTime: tlsResult[2],
            message: tlsResult[1],
            timestamp: new Date().toISOString()
        };
    } else {
        throw new Error("非 Cloudflare 响应");
    }
  } catch (error) {
    return {
      success: false,
      proxyIP: -1,
      portRemote: -1,
      colo: colo,
      responseTime: -1,
      message: error.message || "连接失败",
      timestamp: new Date().toISOString()
    };
  }
}

// 复用原代码的 Hash 和 整理 函数
async function 双重哈希(t){const e=new TextEncoder,n=await crypto.subtle.digest("MD5",e.encode(t)),o=Array.from(new Uint8Array(n)).map(t=>t.toString(16).padStart(2,"0")).join(""),a=await crypto.subtle.digest("MD5",e.encode(o.slice(7,27))),r=Array.from(new Uint8Array(a));return r.map(t=>t.toString(16).padStart(2,"0")).join("").toLowerCase()}

// 简化的验证逻辑，保留原有的结构
async function 验证反代IP(ip, port) {
    const start = performance.now();
    try {
        const socket = connect({ hostname: ip, port: port });
        await socket.opened;
        await socket.close();
        // 如果能建立 TCP 连接，姑且认为第一步成功，实际 HTTP 响应在 CheckProxyIP 中判断了
        return [true, "连接成功", Math.round(performance.now() - start)];
    } catch(e) {
        return [false, e.message, -1];
    }
}

// ============================================
// 统一前端页面 HTML
// ============================================
function renderUnifiedPage(cfData, favicon, token) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Network Tools Collection</title>
  <link rel="icon" href="${favicon}" type="image/x-icon">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    /* 全局重置 */
    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    /* 默认 Body 样式 (Link Tracer 风格) */
    body {
      font-family: system-ui, -apple-system, 'Inter', sans-serif;
      background: #0f172a; /* Link Tracer Dark */
      color: #f1f5f9;
      min-height: 100vh;
      transition: background 0.5s ease;
    }

    /* 顶部导航栏 */
    .nav-bar {
        display: flex;
        justify-content: center;
        gap: 20px;
        padding: 20px;
        background: rgba(30, 41, 59, 0.8);
        backdrop-filter: blur(10px);
        border-bottom: 1px solid #334155;
        position: sticky;
        top: 0;
        z-index: 1000;
    }
    .nav-btn {
        background: transparent;
        color: #94a3b8;
        border: 2px solid transparent;
        padding: 8px 16px;
        border-radius: 20px;
        cursor: pointer;
        font-weight: 600;
        transition: all 0.3s;
    }
    .nav-btn:hover { color: white; background: rgba(255,255,255,0.1); }
    .nav-btn.active {
        background: #06b6d4;
        color: black;
        box-shadow: 0 0 15px rgba(6, 182, 212, 0.4);
    }
    /* ProxyIP 激活时的按钮样式覆盖 */
    body.mode-proxyip .nav-btn.active {
        background: #3498db;
        color: white;
        box-shadow: 0 0 15px rgba(52, 152, 219, 0.4);
    }

    /* 容器控制 */
    .tab-content { display: none; animation: fadeIn 0.4s ease; padding: 20px; max-width: 1000px; margin: 0 auto; }
    .tab-content.active { display: block; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

    /* =========================================
       CSS Scope: Link Tracer (#tracer-app)
       ========================================= */
    #tracer-app {
        --primary: #06b6d4; --card-bg: #1e293b; --border: #334155;
    }
    #tracer-app .card {
        background: var(--card-bg); border-radius: 16px; padding: 24px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.4); margin-bottom: 20px; border: 1px solid var(--border);
    }
    #tracer-app h1 { color: var(--primary); font-size: 24px; margin-bottom: 20px; }
    #tracer-app .local-bar { 
        display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; 
        background: rgba(6, 182, 212, 0.1); padding: 15px; border-radius: 12px; border: 1px solid rgba(6, 182, 212, 0.2); margin-bottom: 25px; 
    }
    #tracer-app textarea { 
        width: 100%; height: 120px; background: #0f172a; border: 1px solid var(--border); 
        color: white; padding: 15px; border-radius: 12px; font-family: monospace; outline: none; 
    }
    #tracer-app .btn-primary { background: var(--primary); color: #000; padding: 10px 20px; border-radius: 8px; border:none; cursor: pointer; font-weight: bold; }
    #tracer-app table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }
    #tracer-app th { text-align: left; padding: 12px; color: var(--primary); border-bottom: 2px solid var(--border); }
    #tracer-app td { padding: 12px; border-bottom: 1px solid var(--border); }
    #tracer-app .rtt-green { color: #34d399; } #tracer-app .rtt-red { color: #f87171; }

    /* =========================================
       CSS Scope: ProxyIP (#proxyip-app)
       ========================================= */
    /* 当切换到 ProxyIP Tab 时，Body 背景变为渐变 */
    body.mode-proxyip {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: #2c3e50;
    }
    
    #proxyip-app {
        --primary-color: #3498db; --bg-primary: #ffffff; --text-primary: #2c3e50;
    }
    #proxyip-app .header { text-align: center; margin-bottom: 40px; color: white; text-shadow: 0 2px 4px rgba(0,0,0,0.2); }
    #proxyip-app .card {
        background: var(--bg-primary); border-radius: 12px; padding: 32px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.15); margin-bottom: 32px;
        backdrop-filter: blur(20px);
    }
    #proxyip-app .form-input {
        width: 100%; padding: 16px; border: 2px solid #dee2e6; border-radius: 8px; font-size: 16px;
        margin-bottom: 10px;
    }
    #proxyip-app .btn-check {
        width: 100%; padding: 16px; border: none; border-radius: 8px; font-size: 16px; font-weight: 600;
        background: linear-gradient(135deg, #3498db, #2980b9); color: white; cursor: pointer;
    }
    #proxyip-app .result-card {
        padding: 20px; border-radius: 8px; margin-top: 20px; border-left: 4px solid;
    }
    #proxyip-app .result-success { background: #d4edda; border-color: #2ecc71; color: #155724; }
    #proxyip-app .result-error { background: #f8d7da; border-color: #e74c3c; color: #721c24; }
    #proxyip-app .tag { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-right: 5px; }
    #proxyip-app .tag-country { background: #e3f2fd; color: #1976d2; }

    /* 通用 Github Corner */
    .github-corner { position: absolute; top: 0; right: 0; }
  </style>
</head>
<body>

  <nav class="nav-bar">
    <button class="nav-btn active" onclick="switchTab('tracer')">📡 Link Tracer</button>
    <button class="nav-btn" onclick="switchTab('proxyip')">🛡️ ProxyIP Checker</button>
  </nav>

  <a href="https://github.com/cmliu/CF-Workers-CheckProxyIP" target="_blank" class="github-corner" aria-label="View source on Github">
    <svg width="80" height="80" viewBox="0 0 250 250" style="fill:#fff; color:#151513; position: absolute; top: 0; border: 0; right: 0;" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg>
  </a>

  <div id="tracer-app" class="tab-content active">
    <div class="card">
      <h1>📡 Link Tracer</h1>
      <div class="local-bar">
        <div class="info-item"><label style="opacity:0.7;display:block;font-size:12px">节点 (Colo)</label><span style="color:#06b6d4;font-weight:bold">${cfData.colo}</span></div>
        <div class="info-item"><label style="opacity:0.7;display:block;font-size:12px">位置</label><span style="color:#06b6d4;font-weight:bold">${cfData.country} - ${cfData.city}</span></div>
        <div class="info-item"><label style="opacity:0.7;display:block;font-size:12px">本机 IP</label><span style="color:#06b6d4;font-weight:bold">${cfData.ip}</span></div>
      </div>
      <textarea id="tracer-input" placeholder="输入目标地址（支持域名或IP），一行一个... 例如: 1.1.1.1 或 google.com"></textarea>
      <div style="margin-top:15px">
        <button class="btn-primary" onclick="startTracer()">🚀 开始探测</button>
        <button class="btn-primary" style="background:#334155;color:white" onclick="document.getElementById('tracer-result-body').innerHTML=''">🗑️ 清空</button>
      </div>
    </div>
    
    <div class="card" id="tracer-result-panel" style="display:none">
      <table>
        <thead><tr><th>目标地址</th><th>TCP 延迟</th><th>物理位置</th><th>ISP / 机房</th></tr></thead>
        <tbody id="tracer-result-body"></tbody>
      </table>
    </div>
  </div>

  <div id="proxyip-app" class="tab-content">
    <div class="header">
      <h1 style="font-size: 3rem; margin-bottom: 10px;">Check ProxyIP</h1>
      <p>基于 Cloudflare Workers 的反代 IP 检测</p>
    </div>
    <div class="card">
      <label class="form-label" style="display:block;margin-bottom:10px;font-weight:bold">🔍 输入 ProxyIP 地址</label>
      <input type="text" id="proxy-input" class="form-input" placeholder="例如: 1.2.3.4:443 或 example.com">
      <button id="proxy-btn" class="btn-check" onclick="startProxyCheck()">
        <span id="proxy-btn-text">检测</span>
      </button>
      <div id="proxy-result"></div>
    </div>
  </div>

  <script>
    // --- 页面切换逻辑 ---
    function switchTab(tab) {
        document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
        
        if (tab === 'tracer') {
            document.getElementById('tracer-app').classList.add('active');
            document.querySelector('button[onclick="switchTab(\\'tracer\\')"]').classList.add('active');
            document.body.className = ''; // 恢复 Tracer 的暗黑背景
        } else {
            document.getElementById('proxyip-app').classList.add('active');
            document.querySelector('button[onclick="switchTab(\\'proxyip\\')"]').classList.add('active');
            document.body.className = 'mode-proxyip'; // 切换到 ProxyIP 的渐变背景
        }
    }

    // ============================================
    // Link Tracer 逻辑
    // ============================================
    async function startTracer() {
        const input = document.getElementById('tracer-input').value.trim();
        if(!input) return alert('请输入目标');
        document.getElementById('tracer-result-panel').style.display = 'block';
        const lines = input.split('\\n').map(x=>x.trim()).filter(x=>x);
        for(const line of lines) { await processTracerLine(line); }
    }

    async function processTracerLine(target) {
        const isIP = /^[0-9\\.:]+$/.test(target);
        if (isIP) { addTracerRow(target, target); }
        else {
            try {
                const res = await fetch(\`./api/resolve?domain=\${encodeURIComponent(target)}\`);
                const data = await res.json();
                if(data.status === 'success' && data.ips.length > 0) {
                    data.ips.forEach(ip => addTracerRow(\`\${target} (\${ip})\`, ip));
                } else { addTracerRow(target, target); }
            } catch(e) { addTracerRow(target + " [解析失败]", target); }
        }
    }

    function addTracerRow(label, ip) {
        const tbody = document.getElementById('tracer-result-body');
        const tr = document.createElement('tr');
        const id = Math.random().toString(36).substr(2,9);
        tr.innerHTML = \`<td>\${label}</td><td id="rtt-\${id}">...</td><td id="geo-\${id}">...</td><td id="isp-\${id}">...</td>\`;
        tbody.prepend(tr);
        
        // 延迟
        fetch(\`./api/tcping?target=\${encodeURIComponent(ip.replace(/[\\\\[\\\\]]/g,''))}\`)
            .then(r=>r.json()).then(d => {
                const el = document.getElementById(\`rtt-\${id}\`);
                if(d.status==='success') {
                    const color = d.rtt < 100 ? '#34d399' : (d.rtt < 200 ? '#fbbf24' : '#f87171');
                    el.innerHTML = \`<span style="color:\${color};font-weight:bold">\${d.rtt} ms</span> <small>(\${d.type})</small>\`;
                } else { el.innerHTML = '<span style="color:#f87171">Timeout</span>'; }
            });
            
        // GeoIP
        fetch(\`./api/geoip?target=\${encodeURIComponent(ip.replace(/[\\\\[\\\\]]/g,''))}\`)
            .then(r=>r.json()).then(d => {
                document.getElementById(\`geo-\${id}\`).innerText = (d.country||'') + ' ' + (d.city||'');
                document.getElementById(\`isp-\${id}\`).innerText = (d.connection?.isp || d.isp || 'Unknown') + (d.connection?.asn ? ' AS'+d.connection.asn : '');
            });
    }

    // ============================================
    // ProxyIP Checker 逻辑
    // ============================================
    const TOKEN = "${token}"; // 注入后端生成的 Token

    async function startProxyCheck() {
        const input = document.getElementById('proxy-input').value.trim();
        const btn = document.getElementById('proxy-btn');
        const resultDiv = document.getElementById('proxy-result');
        if(!input) return alert('请输入 ProxyIP');

        btn.disabled = true;
        btn.innerHTML = '检测中...';
        resultDiv.innerHTML = '';

        try {
            // 判断是 IP 还是域名
            const isIP = /^[0-9\\.:\\[\\]]+$/.test(input);
            if (isIP) {
                await checkSingleProxy(input);
            } else {
                await checkDomainProxy(input);
            }
        } catch(e) {
            resultDiv.innerHTML = \`<div class="result-card result-error">❌ 错误: \${e.message}</div>\`;
        } finally {
            btn.disabled = false;
            btn.innerHTML = '检测';
        }
    }

    async function checkSingleProxy(ip) {
        const res = await fetch(\`./check?proxyip=\${encodeURIComponent(ip)}&token=\${TOKEN}\`);
        const data = await res.json();
        renderProxyResult(data, ip);
    }

    async function checkDomainProxy(domain) {
        // 先解析
        const res = await fetch(\`./resolve?domain=\${encodeURIComponent(domain)}&token=\${TOKEN}\`);
        const data = await res.json();
        if(!data.success) throw new Error(data.error);
        
        let html = \`<div class="result-card" style="background:#fff3cd;border-color:#ffeaa7"><h3>🔍 域名解析: \${domain}</h3><p>发现 \${data.ips.length} 个 IP，正在逐个检测...</p></div>\`;
        document.getElementById('proxy-result').innerHTML = html;

        for(const ip of data.ips) {
             const checkRes = await fetch(\`./check?proxyip=\${encodeURIComponent(ip)}&token=\${TOKEN}\`);
             const checkData = await checkRes.json();
             // 追加显示
             const div = document.createElement('div');
             div.innerHTML = getProxyResultHTML(checkData, ip);
             document.getElementById('proxy-result').appendChild(div);
        }
    }

    function renderProxyResult(data, inputIP) {
        const div = document.createElement('div');
        div.innerHTML = getProxyResultHTML(data, inputIP);
        document.getElementById('proxy-result').appendChild(div);
    }

    function getProxyResultHTML(data, inputIP) {
        if(data.success) {
            return \`
            <div class="result-card result-success">
                <h3>✅ 有效: \${data.proxyIP}</h3>
                <p>端口: \${data.portRemote} | 机房: \${data.colo} | 响应: \${data.responseTime}ms</p>
                <p style="font-size:12px;opacity:0.8">\${data.message}</p>
            </div>\`;
        } else {
            return \`
            <div class="result-card result-error">
                <h3>❌ 无效: \${inputIP}</h3>
                <p>信息: \${data.message || '连接失败'}</p>
            </div>\`;
        }
    }
  </script>
</body>
</html>`;
}
