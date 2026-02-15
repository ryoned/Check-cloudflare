import { connect } from "cloudflare:sockets";

// --- 全局变量 (来自 z) ---
let 临时TOKEN, 永久TOKEN;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const hostname = url.hostname;
    
    // --- Token 生成逻辑 (来自 z) ---
    const UA = request.headers.get('User-Agent') || 'null';
    const currentDate = new Date();
    const timestamp = Math.ceil(currentDate.getTime() / (1000 * 60 * 31)); // 每31分钟一个时间戳
    临时TOKEN = await 双重哈希(url.hostname + timestamp + UA);
    永久TOKEN = env.TOKEN || 临时TOKEN;

    // --- 后端 API 接口 ---

    // 1. TCP 延迟检测 (来自 a)
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
        return new Response(JSON.stringify({ status: 'success', rtt, type: 'TCP' }), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      } catch (e) {
        // TCP 失败，尝试 HTTP (针对 Cloudflare IP)
        try {
          const fetchStart = performance.now();
          await fetch(`https://${target}/cdn-cgi/trace`, { method: 'HEAD', cache: 'no-store' });
          const rtt = Math.round(performance.now() - fetchStart);
          return new Response(JSON.stringify({ status: 'success', rtt, type: 'HTTP(CF)' }), {
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
          });
        } catch (err) {
          return new Response(JSON.stringify({ status: 'error', message: e.message }), {
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
          });
        }
      }
    }

    // 2. ProxyIP 有效性检测 (来自 z 的 /check 接口)
    if (path === '/check') {
      // Token 验证
      if (env.TOKEN) {
        if (!url.searchParams.has('token') || url.searchParams.get('token') !== 永久TOKEN) {
          return new Response(JSON.stringify({ status: "error", message: "Invalid Token" }), { status: 403 });
        }
      }
      
      const proxyIP = url.searchParams.get('proxyip');
      if (!proxyIP) return new Response('Missing proxyip', { status: 400 });

      const colo = request.cf?.colo || 'CF';
      // 调用 z 的核心检测函数
      const result = await CheckProxyIP(proxyIP, colo);

      return new Response(JSON.stringify(result), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    // 3. 地理位置查询 (保留 a 的 ipwho.is 逻辑)
    if (path === '/api/geoip') {
      const target = url.searchParams.get('target');
      if (!target) return new Response('Missing target', { status: 400 });
      try {
        const response = await fetch(`https://ipwho.is/${target}?lang=zh-CN`);
        const data = await response.json();
        return new Response(JSON.stringify(data), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ status: 'fail' }), { status: 500 });
      }
    }

    // 4. 域名解析 (合并逻辑，使用 z 的增强版解析)
    if (path === '/api/resolve' || path === '/resolve') {
      const domain = url.searchParams.get('domain');
      if (!domain) return new Response('Missing domain', { status: 400 });
      try {
        const ips = await resolveDomain(domain);
        return new Response(JSON.stringify({ status: 'success', ips }), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ status: 'error', message: e.message }), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      }
    }

    // --- 前端页面渲染 (UI 以 a 为主，注入 token) ---
    const currentColo = request.cf?.colo || '未知';
    const currentCity = request.cf?.city || '未知';
    const currentCountry = request.cf?.country || '未知';
    const currentIP = request.headers.get('CF-Connecting-IP') || '未知';

    return new Response(renderHTML(currentColo, currentCity, currentCountry, currentIP, 临时TOKEN), {
      headers: { "Content-Type": "text/html;charset=UTF-8" }
    });
  }
};

// ============================================
// 核心逻辑函数库 (来自 z_worker.js)
// ============================================

async function 双重哈希(文本) {
  const 编码器 = new TextEncoder();
  const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
  const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
  const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');
  const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
  const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
  const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');
  return 第二次十六进制.toLowerCase();
}

async function resolveDomain(domain) {
  domain = domain.includes(':') ? domain.split(':')[0] : domain;
  const endpoints = [
    { url: 'https://dns.google/resolve', name: 'Google' },
    { url: 'https://223.5.5.5/resolve', name: 'AliDNS' }
  ];
  for (const endpoint of endpoints) {
    try {
      const [v4, v6] = await Promise.all([
        fetch(`${endpoint.url}?name=${domain}&type=A`).then(r => r.json()),
        fetch(`${endpoint.url}?name=${domain}&type=AAAA`).then(r => r.json())
      ]);
      const ips = new Set();
      if (v4.Answer) v4.Answer.filter(r => r.type === 1).forEach(r => ips.add(r.data));
      if (v6.Answer) v6.Answer.filter(r => r.type === 28).forEach(r => ips.add(r.data)); // IPv6不需要加括号，前端处理
      if (ips.size > 0) return Array.from(ips);
    } catch (e) { continue; }
  }
  return [domain];
}

async function CheckProxyIP(proxyIP, colo = 'CF') {
  // 格式处理
  let portRemote = 443;
  if (proxyIP.includes('.tp')) {
    const portMatch = proxyIP.match(/\.tp(\d+)\./);
    if (portMatch) portRemote = parseInt(portMatch[1]);
  } else if (proxyIP.includes('[') && proxyIP.includes(']:')) {
    portRemote = parseInt(proxyIP.split(']:')[1]);
    proxyIP = proxyIP.split(']:')[0] + ']';
  } else if (proxyIP.includes(':') && !proxyIP.includes('[')) {
    portRemote = parseInt(proxyIP.split(':')[1]);
    proxyIP = proxyIP.split(':')[0];
  }

  const tcpSocket = connect({ hostname: proxyIP, port: portRemote });

  try {
    // 构造 HTTP 请求模拟
    const httpRequest =
      "GET /cdn-cgi/trace HTTP/1.1\r\n" +
      "Host: speed.cloudflare.com\r\n" +
      "User-Agent: CheckProxyIP/LinkTracer\r\n" +
      "Connection: close\r\n\r\n";

    const writer = tcpSocket.writable.getWriter();
    await writer.write(new TextEncoder().encode(httpRequest));
    writer.releaseLock();

    const reader = tcpSocket.readable.getReader();
    let responseData = new Uint8Array(0);
    
    // 读取响应
    while (true) {
      const { value, done } = await Promise.race([
        reader.read(),
        new Promise(resolve => setTimeout(() => resolve({ done: true }), 5000))
      ]);
      if (done) break;
      if (value) {
        const newData = new Uint8Array(responseData.length + value.length);
        newData.set(responseData);
        newData.set(value, responseData.length);
        responseData = newData;
        const txt = new TextDecoder().decode(responseData);
        if (txt.includes("\r\n\r\n")) break; 
      }
    }
    reader.releaseLock();
    await tcpSocket.close();

    const responseText = new TextDecoder().decode(responseData);
    // 简单验证是否是 Cloudflare 的响应
    const isValid = responseText.includes("400 Bad Request") && responseText.includes("plain HTTP request was sent to HTTPS port");

    if (isValid) {
      // 进一步进行 TLS 握手验证
      const tlsResult = await 验证反代IP(proxyIP, portRemote);
      return {
        success: tlsResult[0],
        proxyIP: proxyIP,
        portRemote: portRemote,
        colo: colo,
        responseTime: tlsResult[2], // TLS RTT
        message: tlsResult[1]
      };
    } else {
      return { success: false, message: "非 CF 节点响应" };
    }
  } catch (error) {
    return { success: false, message: error.message };
  }
}

async function 验证反代IP(ip, port) {
  const start = performance.now();
  try {
    const socket = await 带超时连接({ hostname: ip, port: port }, 2000);
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    await writer.write(构建TLS握手());
    
    const { value, 超时 } = await 带超时读取(reader, 2000);
    if (超时 || !value || value.length === 0) throw new Error("TLS 握手超时");
    
    // 0x16 表示 TLS Handshake
    if (value[0] === 0x16) {
      try { reader.cancel(); socket.close(); } catch(e){}
      return [true, "有效", Math.round(performance.now() - start)];
    } else {
      throw new Error("非 TLS 响应");
    }
  } catch (e) {
    return [false, e.message, -1];
  }
}

function 构建TLS握手() {
  // Client Hello 数据包
  const hex = '16030100c6010000c20303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000062c02bc02fc02cc030cca9cca8c013c014009c009d002f0035000a010000370000000b000403000102000d0016001406010603050105030401040303010303020102030017000000230000000500050100000000001200000010000e000c02683208687474702f312e31000b00020100';
  return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

async function 带超时连接(options, timeout) {
  const socket = connect(options);
  await Promise.race([
    socket.opened,
    new Promise((_, r) => setTimeout(() => r(new Error("Connect Timeout")), timeout))
  ]);
  return socket;
}

function 带超时读取(reader, timeout) {
  return new Promise(resolve => {
    const timer = setTimeout(() => resolve({ value: null, 超时: true }), timeout);
    reader.read().then(res => { clearTimeout(timer); resolve({ ...res, 超时: false }); });
  });
}

// ============================================
// 前端 UI (以 a_worker.js 为主，融合功能)
// ============================================

function renderHTML(colo, city, country, ip, token) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Link Tracer & Proxy Checker</title>
  <style>
    /* 核心样式：保留 a_worker.js 的设计 */
    :root { --primary: #06b6d4; --bg: #0f172a; --card: #1e293b; --text: #f1f5f9; --border: #334155; }
    body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }
    .container { max-width: 1100px; margin: 0 auto; }
    .card { background: var(--card); border-radius: 16px; padding: 24px; box-shadow: 0 4px 20px rgba(0,0,0,0.4); margin-bottom: 20px; border: 1px solid var(--border); }
    h1 { margin: 0 0 20px 0; font-size: 24px; color: var(--primary); display: flex; align-items: center; gap: 10px; }
    .local-bar { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; background: rgba(6, 182, 212, 0.1); padding: 15px; border-radius: 12px; margin-bottom: 20px; }
    .info-item label { display: block; font-size: 12px; opacity: 0.7; margin-bottom: 4px; }
    .info-item span { font-weight: 600; font-size: 15px; color: var(--primary); }
    
    textarea { width: 100%; height: 120px; background: #0f172a; border: 1px solid var(--border); color: white; padding: 15px; border-radius: 12px; font-family: monospace; resize: vertical; box-sizing: border-box; outline: none; transition: 0.2s; }
    textarea:focus { border-color: var(--primary); }
    
    .controls { margin-top: 15px; display: flex; gap: 10px; flex-wrap: wrap; }
    .btn { padding: 10px 20px; border-radius: 8px; border: none; font-weight: 600; cursor: pointer; transition: 0.2s; display: inline-flex; align-items: center; gap: 6px; }
    .btn-primary { background: var(--primary); color: #000; }
    .btn-ghost { background: var(--border); color: white; }
    .btn:hover { filter: brightness(1.1); }
    #file-input { display: none; }
    
    .history { margin-top: 15px; display: flex; gap: 8px; overflow-x: auto; padding-bottom: 5px; }
    .tag { background: #334155; padding: 4px 10px; border-radius: 20px; font-size: 12px; cursor: pointer; white-space: nowrap; border: 1px solid transparent; }
    .tag:hover { border-color: var(--primary); color: var(--primary); }
    
    table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; min-width: 800px; }
    th { text-align: left; padding: 12px; color: var(--primary); border-bottom: 2px solid var(--border); font-weight: 600; }
    td { padding: 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    
    .rtt-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 13px; }
    .rtt-green { background: rgba(16, 185, 129, 0.2); color: #34d399; }
    .rtt-yellow { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
    .rtt-red { background: rgba(239, 68, 68, 0.2); color: #f87171; }
    
    .status-ok { color: #34d399; font-weight: bold; }
    .status-fail { color: #f87171; }
    .type-label { font-size: 10px; opacity: 0.5; margin-left: 4px; border: 1px solid rgba(255,255,255,0.2); padding: 1px 3px; border-radius: 3px; }
    .target-sub { font-size: 12px; opacity: 0.6; display: block; margin-top: 2px; }
    .loading-spin { display: inline-block; width: 12px; height: 12px; border: 2px solid var(--primary); border-top-color: transparent; border-radius: 50%; animation: spin 1s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>

<div class="container">
  <div class="card">
    <h1>📡 Link Tracer <span style="font-size:12px; opacity:0.6; color:var(--text); margin-left:auto;">& Proxy Checker</span></h1>
    
    <div class="local-bar">
      <div class="info-item"><label>当前节点 (Colo)</label><span>${colo}</span></div>
      <div class="info-item"><label>物理位置</label><span>${country} - ${city}</span></div>
      <div class="info-item"><label>本机 IP</label><span>${ip}</span></div>
    </div>

    <textarea id="input-area" placeholder="输入目标地址（支持域名或IP），一行一个...&#10;例如：&#10;1.2.3.4&#10;google.com"></textarea>
    
    <div class="controls">
      <button class="btn btn-primary" onclick="startBatch()">🚀 开始探测</button>
      <button class="btn btn-ghost" onclick="document.getElementById('file-input').click()">📂 上传 TXT</button>
      <input type="file" id="file-input" accept=".txt" onchange="handleFile(this)">
      <button class="btn btn-ghost" onclick="clearTable()">🗑️ 清空表格</button>
    </div>

    <div class="history" id="history-box"></div>
  </div>

  <div class="card" id="result-panel" style="display:none;">
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th width="30%">目标地址 (Target)</th>
            <th width="15%">TCP 延迟</th>
            <th width="20%">Proxy 状态 (TLS)</th>
            <th width="35%">地理位置 / ISP</th>
          </tr>
        </thead>
        <tbody id="result-body"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
  // 注入 Token 用于 Proxy 检测
  const API_TOKEN = "${token}";
  
  const historyKey = 'tracer_history_merged';
  const inputArea = document.getElementById('input-area');
  const resultBody = document.getElementById('result-body');
  
  function saveHistory(val) {
    if(!val) return;
    let list = JSON.parse(localStorage.getItem(historyKey) || '[]');
    const preview = val.split('\\n')[0].substring(0, 15) + (val.length>15?'...':'');
    list = list.filter(i => i.val !== val);
    list.unshift({ name: preview, val: val });
    if(list.length > 5) list.pop();
    localStorage.setItem(historyKey, JSON.stringify(list));
    renderHistory();
  }

  function renderHistory() {
    const list = JSON.parse(localStorage.getItem(historyKey) || '[]');
    const box = document.getElementById('history-box');
    box.innerHTML = list.map(item => 
      \`<div class="tag" onclick="fillInput('\${encodeURIComponent(item.val)}')">\${item.name}</div>\`
    ).join('');
  }
  
  window.fillInput = (val) => { inputArea.value = decodeURIComponent(val); }
  
  window.handleFile = (input) => {
    const file = input.files[0];
    if(file) {
      const reader = new FileReader();
      reader.onload = e => inputArea.value = e.target.result;
      reader.readAsText(file);
    }
  }

  window.clearTable = () => {
    resultBody.innerHTML = '';
    document.getElementById('result-panel').style.display = 'none';
  }

  window.startBatch = async () => {
    const raw = inputArea.value.trim();
    if(!raw) return alert('请输入目标地址');
    saveHistory(raw);
    
    document.getElementById('result-panel').style.display = 'block';
    const lines = raw.split('\\n').map(x => x.trim()).filter(x => x);

    for (const target of lines) {
      await processLine(target);
    }
  }

  async function processLine(target) {
    const isIP = /^[0-9\\.:]+$/.test(target);
    
    if (isIP) {
      addResultRow(target, target);
    } else {
      // 域名解析
      const tempId = 'resolving-' + Math.random().toString(36).substr(2, 9);
      addPlaceholderRow(target, tempId);
      
      try {
        const res = await fetch(\`./api/resolve?domain=\${encodeURIComponent(target)}\`);
        const data = await res.json();
        const placeholder = document.getElementById(tempId);
        if(placeholder) placeholder.remove();

        if (data.status === 'success' && data.ips.length > 0) {
          for (const ip of data.ips) {
            addResultRow(\`\${target} (\${ip})\`, ip);
          }
        } else {
          addResultRow(target, target); 
        }
      } catch(e) {
        if(document.getElementById(tempId)) document.getElementById(tempId).remove();
        addResultRow(target + " [解析失败]", target);
      }
    }
  }

  function addPlaceholderRow(label, id) {
    const tr = document.createElement('tr');
    tr.id = id;
    tr.innerHTML = \`
      <td>\${label}</td>
      <td colspan="3" style="color:#94a3b8"><span class="loading-spin"></span> 正在解析...</td>
    \`;
    resultBody.prepend(tr);
  }

  function addResultRow(displayLabel, realTarget) {
    const tr = document.createElement('tr');
    const rowId = 'row-' + Math.random().toString(36).substr(2, 9);
    tr.id = rowId;
    
    tr.innerHTML = \`
      <td>
        <div>\${displayLabel.split(' (')[0]}</div>
        \${displayLabel.includes('(') ? \`<span class="target-sub">\${displayLabel.split(' (')[1].replace(')', '')}</span>\` : ''}
      </td>
      <td id="\${rowId}-rtt"><span class="loading-spin"></span></td>
      <td id="\${rowId}-proxy"><span class="loading-spin"></span></td>
      <td id="\${rowId}-geo">...</td>
    \`;
    resultBody.prepend(tr);

    const cleanIP = realTarget.replace(/[\\[\\]]/g, '');
    
    // 1. TCP 延迟检测 (Link Tracer 逻辑)
    fetch(\`./api/tcping?target=\${encodeURIComponent(cleanIP)}\`)
      .then(r => r.json())
      .then(d => {
        const el = document.getElementById(\`\${rowId}-rtt\`);
        if(d.status === 'success') {
          let cls = 'rtt-green';
          if(d.rtt > 100) cls = 'rtt-yellow';
          if(d.rtt > 250) cls = 'rtt-red';
          const typeTag = d.type ? \`<span class="type-label">\${d.type}</span>\` : '';
          el.innerHTML = \`<span class="rtt-badge \${cls}">\${d.rtt} ms</span>\${typeTag}\`;
        } else {
          el.innerHTML = \`<span style="color:#ef4444; font-size:12px">超时</span>\`;
        }
      });

    // 2. ProxyIP 有效性检测 (集成 z 的逻辑)
    fetch(\`./check?proxyip=\${encodeURIComponent(cleanIP)}&token=\${API_TOKEN}\`)
      .then(r => r.json())
      .then(d => {
        const el = document.getElementById(\`\${rowId}-proxy\`);
        if(d.success) {
          el.innerHTML = \`<span class="status-ok">✅ 有效</span> <span class="target-sub">\${d.responseTime}ms (TLS)</span>\`;
        } else {
          el.innerHTML = \`<span class="status-fail">❌ 无效</span>\`;
        }
      })
      .catch(e => {
        document.getElementById(\`\${rowId}-proxy\`).innerText = '检测失败';
      });

    // 3. GeoIP 查询 (Link Tracer 逻辑)
    fetch(\`./api/geoip?target=\${encodeURIComponent(cleanIP)}\`)
      .then(r => r.json())
      .then(d => {
        const el = document.getElementById(\`\${rowId}-geo\`);
        const city = d.city || '';
        const country = d.country || '';
        const ispName = d.connection ? (d.connection.isp || d.connection.org) : (d.isp || '未知');
        const asn = d.connection ? d.connection.asn : (d.asn || '');
        
        el.innerHTML = \`
          <div>\${country} \${city}</div>
          <div class="target-sub">\${ispName} (AS\${asn})</div>
        \`;
      });
  }
  
  renderHistory();
</script>

</body>
</html>`;
}
