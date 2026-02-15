import { connect } from "cloudflare:sockets";

// ============================================
// 全局变量
// ============================================
let 临时TOKEN, 永久TOKEN;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const hostname = url.hostname;
    
    // --- 环境初始化 ---
    const 网站图标 = env.ICO || 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';
    const UA = request.headers.get('User-Agent') || 'null';
    const currentDate = new Date();
    const timestamp = Math.ceil(currentDate.getTime() / (1000 * 60 * 31)); 
    
    临时TOKEN = await 双重哈希(url.hostname + timestamp + UA);
    永久TOKEN = env.TOKEN || 临时TOKEN;

    // ============================================
    // API 路由分发
    // ============================================

    // 1. Link Tracer API
    if (path.startsWith('/api/')) {
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
      if (path === '/api/geoip') {
        const target = url.searchParams.get('target');
        try {
          const response = await fetch(`https://ipwho.is/${target}?lang=zh-CN`);
          const data = await response.json();
          return new Response(JSON.stringify(data), { headers: apiHeaders() });
        } catch (e) { return new Response(JSON.stringify({ status: 'fail' }), { status: 500 }); }
      }
      if (path === '/api/resolve') {
        const domain = url.searchParams.get('domain');
        try {
          const ips = await resolveDomain_Tracer(domain);
          return new Response(JSON.stringify({ status: 'success', ips }), { headers: apiHeaders() });
        } catch (e) { return new Response(JSON.stringify({ status: 'error' }), { headers: apiHeaders() }); }
      }
    }

    // 2. ProxyIP API
    if (path.toLowerCase() === '/check') {
      const proxyIP = url.searchParams.get('proxyip');
      if (!proxyIP) return new Response('Missing proxyip', { status: 400 });
      if (env.TOKEN && url.searchParams.get('token') !== 永久TOKEN && url.searchParams.get('token') !== 临时TOKEN) {
         return new Response(JSON.stringify({ status: "error", message: "Invalid Token" }), { status: 403, headers: apiHeaders() });
      }
      const colo = request.cf?.colo || 'CF';
      const result = await CheckProxyIP(proxyIP.toLowerCase(), colo);
      return new Response(JSON.stringify(result, null, 2), { status: result.success ? 200 : 502, headers: apiHeaders() });
    }
    
    else if (path.toLowerCase() === '/resolve') {
      const domain = url.searchParams.get('domain');
      if (env.TOKEN && url.searchParams.get('token') !== 永久TOKEN && url.searchParams.get('token') !== 临时TOKEN) {
         return new Response(JSON.stringify({ status: "error", message: "Invalid Token" }), { status: 403, headers: apiHeaders() });
      }
      try {
        const ips = await resolveDomain_Proxy(domain);
        return new Response(JSON.stringify({ success: true, domain, ips }), { headers: apiHeaders() });
      } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), { status: 500, headers: apiHeaders() });
      }
    }
    
    else if (path.toLowerCase() === '/ip-info') {
      let ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
      if (ip && ip.includes('[')) ip = ip.replace('[', '').replace(']', '');
      try {
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
        const data = await response.json();
        return new Response(JSON.stringify(data, null, 4), { headers: apiHeaders() });
      } catch (error) { return new Response(JSON.stringify({ status: "error" }), { status: 500 }); }
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

    return new Response(renderUnifiedPage(cfData, 网站图标, hostname, 临时TOKEN), {
      headers: { "Content-Type": "text/html;charset=UTF-8" }
    });
  }
};

// ============================================
// 逻辑函数 (后端)
// ============================================

function apiHeaders() { return { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }; }

async function resolveDomain_Tracer(domain) {
  const endpoints = [{ url: 'https://dns.google/resolve' }, { url: 'https://223.5.5.5/resolve' }];
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

async function resolveDomain_Proxy(domain) {
  domain = domain.includes(':') ? domain.split(':')[0] : domain;
  const endpoints = [{ url: 'https://dns.google/resolve' }, { url: 'https://223.5.5.5/resolve' }];
  for (const endpoint of endpoints) {
    try {
      const [v4, v6] = await Promise.all([
        fetch(`${endpoint.url}?name=${domain}&type=A`).then(r => r.ok?r.json():{}),
        fetch(`${endpoint.url}?name=${domain}&type=AAAA`).then(r => r.ok?r.json():{})
      ]);
      const ips = [];
      if (v4.Answer) v4.Answer.filter(r => r.type === 1).forEach(r => ips.push(r.data));
      if (v6.Answer) v6.Answer.filter(r => r.type === 28).forEach(r => ips.push(`[${r.data}]`));
      if (ips.length > 0) return ips;
    } catch (e) { continue; }
  }
  throw new Error('DNS解析失败');
}

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
    await writer.write(new TextEncoder().encode("GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: CheckProxyIP\r\nConnection: close\r\n\r\n"));
    writer.releaseLock();
    const reader = socket.readable.getReader();
    const { value } = await Promise.race([reader.read(), new Promise(r => setTimeout(() => r({}), 5000))]);
    try{await socket.close();}catch(e){}
    
    if (!value) throw new Error("连接超时");
    const text = new TextDecoder().decode(value);
    if ((text.includes("cloudflare") || text.includes("CF-RAY")) && text.includes("400 Bad Request")) {
       const tStart = performance.now();
       try { const s2 = connect({hostname: proxyIP, port: portRemote}); await s2.opened; await s2.close(); } catch(e){}
       return {
         success: true, proxyIP, portRemote, colo, 
         responseTime: Math.round(performance.now() - tStart), 
         message: "验证成功", timestamp: new Date().toISOString()
       };
    }
    return { success: false, proxyIP, portRemote, colo, responseTime: -1, message: "非CF反代或端口无效", timestamp: new Date().toISOString() };
  } catch (error) {
    return { success: false, proxyIP: -1, portRemote: -1, colo, responseTime: -1, message: error.message, timestamp: new Date().toISOString() };
  }
}

async function 双重哈希(t){const e=new TextEncoder,n=await crypto.subtle.digest("MD5",e.encode(t)),o=Array.from(new Uint8Array(n)).map(t=>t.toString(16).padStart(2,"0")).join(""),a=await crypto.subtle.digest("MD5",e.encode(o.slice(7,27))),r=Array.from(new Uint8Array(a));return r.map(t=>t.toString(16).padStart(2,"0")).join("").toLowerCase()}

// ============================================
// 前端 HTML
// ============================================
function renderUnifiedPage(cfData, favicon, hostname, token) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>网络工具集合</title>
  <link rel="icon" href="${favicon}" type="image/x-icon">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    /* === 全局暗黑主题 === */
    :root {
      --bg-color: #0f172a; --card-bg: #1e293b; --border-color: #334155;
      --text-color: #f1f5f9; --text-muted: #94a3b8;
      --primary: #06b6d4;
      --success-bg: rgba(16, 185, 129, 0.2); --success-text: #34d399;
      --error-bg: rgba(239, 68, 68, 0.2); --error-text: #f87171;
      --warning-bg: rgba(245, 158, 11, 0.2); --warning-text: #fbbf24;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', system-ui, sans-serif; min-height: 100vh; background: var(--bg-color); color: var(--text-color); overflow-x: hidden; }

    /* 顶部导航 */
    .nav-container {
        position: fixed; top: 0; left: 0; right: 0; z-index: 9999;
        display: flex; justify-content: center; gap: 15px; padding: 15px;
        background: rgba(15, 23, 42, 0.9); backdrop-filter: blur(10px);
        border-bottom: 1px solid var(--border-color);
    }
    .nav-btn {
        padding: 8px 20px; border-radius: 20px; border: 1px solid var(--border-color);
        background: transparent; color: var(--text-muted); cursor: pointer;
        font-weight: 600; transition: all 0.2s;
    }
    .nav-btn:hover { color: white; border-color: var(--primary); }
    .nav-btn.active { background: var(--primary); color: #0f172a; border-color: var(--primary); box-shadow: 0 0 15px rgba(6, 182, 212, 0.4); }

    /* 容器 */
    .app-container { display: none; padding-top: 80px; animation: fadeIn 0.4s ease; max-width: 1000px; margin: 0 auto; padding-bottom: 40px; padding-left: 20px; padding-right: 20px; }
    .app-container.active { display: block; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

    /* 通用卡片 */
    .card {
        background: var(--card-bg); border-radius: 16px; padding: 24px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.4); margin-bottom: 20px; border: 1px solid var(--border-color);
    }
    h1 { color: var(--primary); font-size: 24px; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }
    .subtitle { font-size: 14px; opacity: 0.7; color: var(--text-muted); font-weight: normal; margin-top: 5px; }

    /* 表单元素 */
    textarea, input[type="text"] {
        width: 100%; background: var(--bg-color); border: 1px solid var(--border-color);
        color: white; padding: 15px; border-radius: 12px; font-family: monospace; outline: none; transition: border 0.2s; font-size: 14px;
    }
    textarea:focus, input[type="text"]:focus { border-color: var(--primary); }
    
    .btn {
        background: var(--primary); color: #000; padding: 10px 20px; border-radius: 8px; border: none; 
        cursor: pointer; font-weight: bold; margin-right: 10px; transition: 0.2s;
    }
    .btn:hover { opacity: 0.9; transform: translateY(-1px); }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-secondary { background: var(--border-color); color: white; }

    /* 表格 */
    table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }
    th { text-align: left; padding: 12px; color: var(--primary); border-bottom: 2px solid var(--border-color); }
    td { padding: 12px; border-bottom: 1px solid var(--border-color); vertical-align: middle; }

    /* === ProxyIP 结果卡片 === */
    .proxy-result-card {
        border-radius: 12px; padding: 20px; margin-top: 15px; border: 1px solid transparent; background: rgba(0,0,0,0.2);
    }
    .res-success { border-color: var(--success-text); background: var(--success-bg); color: var(--success-text); }
    .res-error { border-color: var(--error-text); background: var(--error-bg); color: var(--error-text); }
    .res-warning { border-color: var(--warning-text); background: var(--warning-bg); color: var(--warning-text); }
    
    .res-header { font-size: 18px; font-weight: bold; margin-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 10px; }
    .res-details { color: var(--text-color); font-size: 14px; line-height: 1.8; }
    .res-details strong { color: var(--primary); margin-right: 8px; }

    /* API Docs */
    .api-docs { background: var(--card-bg); border-radius: 16px; padding: 24px; margin-top: 40px; border: 1px solid var(--border-color); }
    .code-block { background: #0f172a; color: #a5b4fc; padding: 15px; border-radius: 8px; font-family: monospace; border: 1px solid var(--border-color); overflow-x: auto; margin: 10px 0; }
    .hl-verb { color: var(--primary); font-weight: bold; }
    .hl-param { color: #f472b6; }

    /* Github Corner */
    .github-corner svg { fill: var(--border-color); color: var(--bg-color); position: absolute; top: 0; right: 0; border: 0; width: 80px; height: 80px; }
    .github-corner:hover .octo-arm { animation: octocat-wave 560ms ease-in-out; }
    @keyframes octocat-wave { 0%,100%{transform:rotate(0)} 20%,60%{transform:rotate(-25deg)} 40%,80%{transform:rotate(10deg)} }
  </style>
</head>
<body>

  <nav class="nav-container">
    <button class="nav-btn active" onclick="switchTab('tracer')">📡 Link Tracer</button>
    <button class="nav-btn" onclick="switchTab('proxy')">🛡️ Check ProxyIP</button>
  </nav>

  <a href="https://github.com/cmliu/CF-Workers-CheckProxyIP" target="_blank" class="github-corner" aria-label="View source on Github">
    <svg viewBox="0 0 250 250" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg>
  </a>

  <div id="tracer-app" class="app-container active">
    <div class="card">
      <h1>📡 Link Tracer <span class="subtitle">Advanced Network Tools</span></h1>
      <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(150px, 1fr));gap:15px;background:rgba(6,182,212,0.1);padding:15px;border-radius:12px;margin-bottom:20px;border:1px solid rgba(6,182,212,0.2);">
         <div><small style="color:var(--text-muted)">节点 (Colo)</small><br><strong style="color:var(--primary)">${cfData.colo}</strong></div>
         <div><small style="color:var(--text-muted)">位置 (Loc)</small><br><strong style="color:var(--primary)">${cfData.country}</strong></div>
         <div><small style="color:var(--text-muted)">本机 IP</small><br><strong style="color:var(--primary)">${cfData.ip}</strong></div>
      </div>
      <textarea id="trace-input" placeholder="输入目标地址 (例如: 1.1.1.1 或 google.com)，一行一个..."></textarea>
      <div style="margin-top:20px">
        <button class="btn" onclick="startTrace()">🚀 开始探测</button>
        <button class="btn btn-secondary" onclick="document.getElementById('trace-body').innerHTML=''">🗑️ 清空表格</button>
      </div>
    </div>
    <div class="card" id="trace-result" style="display:none">
      <table>
        <thead><tr><th>目标地址</th><th>TCP 延迟</th><th>物理位置</th><th>ISP / 机房</th></tr></thead>
        <tbody id="trace-body"></tbody>
      </table>
    </div>
  </div>

  <div id="proxy-app" class="app-container">
    <div class="card">
      <div style="text-align:center; margin-bottom: 30px;">
        <h1 style="justify-content:center; font-size:32px">Check ProxyIP</h1>
        <p class="subtitle">基于 Cloudflare Workers 的反代 IP 检测 (Dark Mode)</p>
      </div>
      <label style="display:block;margin-bottom:10px;font-weight:bold;color:var(--primary)">🔍 输入 ProxyIP 地址</label>
      <input type="text" id="proxy-input" placeholder="例如: 1.2.3.4:443 或 proxy.example.com">
      <div style="margin-top:20px">
        <button id="proxy-btn" class="btn" onclick="checkProxy()" style="width:100%">开始检测</button>
      </div>
      <div id="summary-card-slot" style="margin-top:20px;"></div>
      <div id="proxy-result" style="margin-top: 20px;"></div>
    </div>
    
    <div class="api-docs">
      <h2 style="color:var(--text-color); border-bottom:1px solid var(--border-color); padding-bottom:10px; margin-bottom:20px;">📚 API 文档</h2>
      <h3 style="color:var(--primary); margin:20px 0 10px;">📍 检查 IP</h3>
      <div class="code-block"><span class="hl-verb">GET</span> /check?proxyip=<span class="hl-param">1.2.3.4:443</span></div>
      <h3 style="color:var(--primary); margin:20px 0 10px;">💡 命令行示例</h3>
      <div class="code-block">curl "https://${hostname}/check?proxyip=1.2.3.4:443"</div>
      <h3 style="color:var(--primary); margin:20px 0 10px;">🔗 JSON 响应</h3>
      <div class="code-block">
{
  "success": true,
  "proxyIP": "1.2.3.4",
  "portRemote": 443,
  "colo": "HKG",
  "responseTime": 166
}
      </div>
    </div>
    <div style="text-align:center; margin-top:40px; color:var(--text-muted); font-size:12px;">
      © 2025 Check ProxyIP | Powered by Cloudflare Workers
    </div>
  </div>

  <script>
    // Tab 切换
    function switchTab(tab) {
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelector(\`.nav-btn[onclick="switchTab('\${tab}')"]\`).classList.add('active');
        document.querySelectorAll('.app-container').forEach(el => el.classList.remove('active'));
        if (tab === 'tracer') document.getElementById('tracer-app').classList.add('active');
        else document.getElementById('proxy-app').classList.add('active');
    }

    // Link Tracer Logic
    async function startTrace() {
        const input = document.getElementById('trace-input').value.trim();
        if(!input) return alert('请输入内容');
        document.getElementById('trace-result').style.display = 'block';
        const lines = input.split('\\n').map(l=>l.trim()).filter(l=>l);
        for(const line of lines) {
            const isIP = /^[0-9\\.:]+$/.test(line);
            if(isIP) addTraceRow(line, line);
            else {
                try {
                   const res = await fetch(\`./api/resolve?domain=\${encodeURIComponent(line)}\`);
                   const d = await res.json();
                   if(d.status==='success' && d.ips.length) d.ips.forEach(ip=>addTraceRow(\`\${line} (\${ip})\`, ip));
                   else addTraceRow(line, line);
                } catch(e) { addTraceRow(line, line); }
            }
        }
    }
    function addTraceRow(label, ip) {
        const tbody = document.getElementById('trace-body');
        const row = document.createElement('tr');
        const id = Math.random().toString(36).substr(2,9);
        row.innerHTML = \`<td>\${label}</td><td id="t-\${id}">...</td><td id="g-\${id}">...</td><td id="i-\${id}">...</td>\`;
        tbody.prepend(row);
        const cleanIP = ip.replace(/[\\[\\]]/g,'');
        fetch(\`./api/tcping?target=\${cleanIP}\`).then(r=>r.json()).then(d=>{
            const el = document.getElementById(\`t-\${id}\`);
            if(d.status==='success') {
               const color = d.rtt<100?'var(--success-text)':(d.rtt<200?'var(--warning-text)':'var(--error-text)');
               el.innerHTML = \`<span style="color:\${color};font-weight:bold">\${d.rtt}ms</span>\`;
            } else el.innerHTML = '<span style="color:var(--error-text)">超时</span>';
        });
        fetch(\`./api/geoip?target=\${cleanIP}\`).then(r=>r.json()).then(d=>{
            document.getElementById(\`g-\${id}\`).innerText = (d.country||'') + ' ' + (d.city||'');
            document.getElementById(\`i-\${id}\`).innerText = d.connection?.isp || d.isp || '-';
        });
    }

    // ProxyIP Logic (并发+详情卡片还原)
    const TOKEN = "${token}";
    async function checkProxy() {
        const input = document.getElementById('proxy-input').value.trim();
        if(!input) return alert('请输入 IP');
        const btn = document.getElementById('proxy-btn');
        const resDiv = document.getElementById('proxy-result');
        const summaryDiv = document.getElementById('summary-card-slot');
        
        btn.disabled = true; btn.innerText = "检测中..."; 
        resDiv.innerHTML = ""; summaryDiv.innerHTML = "";
        
        try {
            const isIP = /^[0-9\\.:\\[\\]]+$/.test(input);
            if(isIP) await checkSingle(input, resDiv);
            else {
                // 1. 解析域名
                const r = await fetch(\`./resolve?domain=\${encodeURIComponent(input)}&token=\${TOKEN}\`);
                const d = await r.json();
                if(!d.success) throw new Error(d.error);
                
                // 2. 渲染详情汇总卡片 (还原用户要求的字段)
                // 尝试解析端口
                let port = 443;
                if(input.includes(':')) port = input.split(':')[1];
                
                summaryDiv.innerHTML = \`
                <div class="proxy-result-card res-warning" id="main-summary">
                   <h3 class="res-header" id="summary-title">🔍 域名解析结果</h3>
                   <div class="res-details">
                      <p><strong>🌐 ProxyIP 域名:</strong> \${input}</p>
                      <p><strong>🔌 端口:</strong> \${port}</p>
                      <p><strong>🏢 机房信息:</strong> <span id="summary-colo">检测中...</span></p>
                      <p><strong>📋 发现IP:</strong> \${d.ips.length} 个</p>
                      <p><strong>🕒 解析时间:</strong> \${new Date().toLocaleString()}</p>
                   </div>
                </div>\`;

                // 3. 并发检测
                let validCount = 0;
                let firstColo = "";
                
                // 使用 map 映射所有请求
                const checks = d.ips.map(async (ip) => {
                    const res = await checkSingle(ip, resDiv, true);
                    if(res && res.success) {
                        validCount++;
                        if(!firstColo) firstColo = res.colo;
                    }
                    return res;
                });
                
                await Promise.allSettled(checks);
                
                // 4. 更新汇总卡片状态
                const summaryCard = document.getElementById('main-summary');
                const title = document.getElementById('summary-title');
                const coloSpan = document.getElementById('summary-colo');
                
                if(validCount === d.ips.length) {
                    summaryCard.className = "proxy-result-card res-success";
                    title.innerText = "✅ 所有IP有效 (" + validCount + "/" + d.ips.length + ")";
                } else if(validCount > 0) {
                    summaryCard.className = "proxy-result-card res-warning";
                    title.innerText = "⚠️ 部分IP有效 (" + validCount + "/" + d.ips.length + ")";
                } else {
                    summaryCard.className = "proxy-result-card res-error";
                    title.innerText = "❌ 所有IP无效";
                }
                
                if(firstColo) coloSpan.innerText = firstColo;
                else coloSpan.innerText = "无有效机房";
            }
        } catch(e) {
            resDiv.innerHTML += \`<div class="proxy-result-card res-error">
                <div class="res-header">❌ 错误</div>
                <div class="res-details">\${e.message}</div>
            </div>\`;
        } finally {
            btn.disabled = false; btn.innerText = "开始检测";
        }
    }

    async function checkSingle(ip, container, append=false) {
        let html = "";
        let resultData = null;
        try {
            const r = await fetch(\`./check?proxyip=\${encodeURIComponent(ip)}&token=\${TOKEN}\`);
            const text = await r.text();
            let d;
            try { d = JSON.parse(text); } catch(e) { throw new Error("Worker Error"); }
            
            resultData = d;
            
            if(d.success) {
                html = \`<div class="proxy-result-card res-success">
                   <div class="res-header">✅ 有效: \${d.proxyIP}</div>
                   <div class="res-details">
                     <span style="margin-right:10px">🔌 端口: \${d.portRemote}</span>
                     <span style="margin-right:10px">🏢 机房: \${d.colo}</span>
                     <span>⚡ 延迟: \${d.responseTime}ms</span>
                   </div>
                 </div>\`;
            } else {
                html = \`<div class="proxy-result-card res-error">
                   <div class="res-header">❌ 无效: \${ip}</div>
                   <div class="res-details">\${d.message||'无法连接'}</div>
                 </div>\`;
            }
        } catch(err) {
             html = \`<div class="proxy-result-card res-error">
               <div class="res-header">❌ 检测失败: \${ip}</div>
               <div class="res-details">\${err.message}</div>
             </div>\`;
        }

        if(append) {
            const div = document.createElement('div'); div.innerHTML = html;
            container.appendChild(div);
        } else container.innerHTML = html;
        
        return resultData;
    }
  </script>
</body>
</html>`;
}
