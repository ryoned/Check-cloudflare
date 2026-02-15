import { connect } from "cloudflare:sockets";

// 全局变量
let 临时TOKEN, 永久TOKEN;

export default {
  async fetch(request, env, ctx) {
    const 网站图标 = env.ICO || 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';
    const url = new URL(request.url);
    const UA = request.headers.get('User-Agent') || 'null';
    const path = url.pathname;
    const hostname = url.hostname;
    const currentDate = new Date();
    const timestamp = Math.ceil(currentDate.getTime() / (1000 * 60 * 31)); // 每31分钟一个时间戳
    
    // 生成 Token
    临时TOKEN = await 双重哈希(url.hostname + timestamp + UA);
    永久TOKEN = env.TOKEN || 临时TOKEN;

    // 路径鉴权：/check
    if (path.toLowerCase() === '/check') {
      if (!url.searchParams.has('proxyip')) return new Response('Missing proxyip parameter', { status: 400 });
      
      // 只有在设置了环境变量 TOKEN 的情况下才强制 API 鉴权
      if (env.TOKEN && url.searchParams.get('token') !== 永久TOKEN) {
        return new Response(JSON.stringify({ status: "error", message: "无效的TOKEN" }), { status: 403 });
      }

      const proxyIP = url.searchParams.get('proxyip').toLowerCase();
      const colo = request.cf?.colo || 'CF';
      const result = await CheckProxyIP(proxyIP, colo);

      return new Response(JSON.stringify(result, null, 2), {
        status: result.success ? 200 : 502,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    } 
    
    // 路径鉴权：/resolve
    else if (path.toLowerCase() === '/resolve') {
      const userToken = url.searchParams.get('token');
      if (env.TOKEN && userToken !== 永久TOKEN && userToken !== 临时TOKEN) {
        return new Response(JSON.stringify({ status: "error", message: "无效的TOKEN" }), { status: 403 });
      }
      
      const domain = url.searchParams.get('domain');
      if (!domain) return new Response('Missing domain', { status: 400 });

      try {
        const ips = await resolveDomain(domain);
        return new Response(JSON.stringify({ success: true, domain, ips }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), { status: 500 });
      }
    } 
    
    // 路径鉴权：/ip-info
    else if (path.toLowerCase() === '/ip-info') {
      const userToken = url.searchParams.get('token');
      if (env.TOKEN && userToken !== 永久TOKEN && userToken !== 临时TOKEN) {
        return new Response(JSON.stringify({ status: "error", message: "无效的TOKEN" }), { status: 403 });
      }

      let ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
      try {
        const response = await fetch(`http://ip-api.com/json/${ip?.replace(/[\[\]]/g, '')}?lang=zh-CN`);
        const data = await response.json();
        return new Response(JSON.stringify(data, null, 4), {
          headers: { "content-type": "application/json; charset=UTF-8", 'Access-Control-Allow-Origin': '*' }
        });
      } catch (error) {
        return new Response(JSON.stringify({ status: "error", message: error.message }), { status: 500 });
      }
    } 
    
    // 首页及跳转逻辑
    else {
      const envKey = env.URL302 ? 'URL302' : (env.URL ? 'URL' : null);
      if (envKey) {
        const URLs = await 整理(env[envKey]);
        const URL = URLs[Math.floor(Math.random() * URLs.length)];
        return envKey === 'URL302' ? Response.redirect(URL, 302) : fetch(new Request(URL, request));
      }

      // --- 关键修复：Token 访问控制 ---
      // 如果设置了 TOKEN 变量
      if (env.TOKEN) {
        const userToken = url.searchParams.get('token');
        // 如果 URL 参数里的 token 不匹配，返回 Nginx 伪装页
        if (userToken !== env.TOKEN) {
          return new Response(await nginx(), {
            headers: { 'Content-Type': 'text/html; charset=UTF-8' },
          });
        }
      }

      if (path.toLowerCase() === '/favicon.ico') {
        return Response.redirect(网站图标, 302);
      }
      
      // 验证通过，显示 HTML 界面，并把当前的永久TOKEN传给前端使用
      return await HTML(hostname, 网站图标, 永久TOKEN);
    }
  }
};

// ================= DNS 解析优化 (Google/Aliyun) =================
async function resolveDomain(domain) {
  domain = domain.includes(':') ? domain.split(':')[0] : domain;
  const endpoints = [
    { url: 'https://dns.google/resolve', name: 'Google DNS' },
    { url: 'https://223.5.5.5/resolve', name: 'AliDNS' }
  ];

  for (const endpoint of endpoints) {
    try {
      const [ipv4Res, ipv6Res] = await Promise.all([
        fetch(`${endpoint.url}?name=${domain}&type=A`),
        fetch(`${endpoint.url}?name=${domain}&type=AAAA`)
      ]);
      if (!ipv4Res.ok || !ipv6Res.ok) continue;
      const [ipv4Data, ipv6Data] = await Promise.all([ipv4Res.json(), ipv6Res.json()]);
      const ips = [];
      if (ipv4Data.Answer) ipv4Data.Answer.filter(r => r.type === 1).forEach(r => ips.push(r.data));
      if (ipv6Data.Answer) ipv6Data.Answer.filter(r => r.type === 28).forEach(r => ips.push(`[${r.data}]`));
      if (ips.length > 0) return ips;
    } catch (error) { continue; }
  }
  throw new Error('DNS解析失败: 所有服务均不可用');
}

// ================= 以下为原有逻辑保持不变 =================

async function CheckProxyIP(proxyIP, colo = 'CF') {
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

  const tcpSocket = connect({ hostname: proxyIP, port: portRemote });

  try {
    const httpRequest = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n";
    const writer = tcpSocket.writable.getWriter();
    await writer.write(new TextEncoder().encode(httpRequest));
    writer.releaseLock();

    const reader = tcpSocket.readable.getReader();
    let responseData = new Uint8Array(0);
    while (true) {
      const { value, done } = await Promise.race([
        reader.read(),
        new Promise(resolve => setTimeout(() => resolve({ done: true }), 5000))
      ]);
      if (done || !value) break;
      const newData = new Uint8Array(responseData.length + value.length);
      newData.set(responseData);
      newData.set(value, responseData.length);
      responseData = newData;
      if (new TextDecoder().decode(responseData).includes("\r\n\r\n")) break;
    }
    reader.releaseLock();
    await tcpSocket.close();

    const responseText = new TextDecoder().decode(responseData);
    if (responseText.includes("cloudflare") && responseText.includes("400 Bad Request")) {
      const tls握手 = await 验证反代IP(proxyIP, portRemote);
      return {
        success: tls握手[0],
        proxyIP: proxyIP,
        portRemote: portRemote,
        colo: colo,
        responseTime: tls握手[2],
        message: tls握手[1],
        timestamp: new Date().toISOString()
      };
    }
    return { success: false, proxyIP, portRemote, colo, message: "无效代理响应", timestamp: new Date().toISOString() };
  } catch (error) {
    return { success: false, proxyIP: -1, portRemote: -1, colo, message: error.message, timestamp: new Date().toISOString() };
  }
}

async function 整理(内容) {
  return 内容.replace(/[\r\n]+/g, '|').replace(/\|+/g, '|').split('|').filter((item, index, self) => item !== '' && self.indexOf(item) === index);
}

async function 双重哈希(文本) {
  const enc = new TextEncoder();
  const h1 = await crypto.subtle.digest('MD5', enc.encode(文本));
  const s1 = Array.from(new Uint8Array(h1)).map(b => b.toString(16).padStart(2, '0')).join('');
  const h2 = await crypto.subtle.digest('MD5', enc.encode(s1.slice(7, 27)));
  return Array.from(new Uint8Array(h2)).map(b => b.toString(16).padStart(2, '0')).join('').toLowerCase();
}

async function 验证反代IP(反代IP地址, 指定端口) {
  const 开始时间 = performance.now();
  let TCP接口 = null;
  try {
    TCP接口 = await 带超时连接({ hostname: 反代IP地址, port: 指定端口 }, 2000);
    const writer = TCP接口.writable.getWriter();
    await writer.write(构建TLS握手());
    writer.releaseLock();
    const reader = TCP接口.readable.getReader();
    const { value, 超时 } = await 带超时读取(reader, 2000);
    if (!超时 && value && value[0] === 0x16) {
      return [true, "验证有效", Math.round(performance.now() - 开始时间)];
    }
  } catch (e) {} finally {
    if (TCP接口) TCP接口.close();
  }
  return [false, "验证失败", -1];
}

function 构建TLS握手() {
  const hex = '1603010200010001fc0303af1f4d78be2002cf63e8c727224cf1ee4a8ac89a0ad04bc54cbed5cd7c830880203d8326ae1d1d076ec749df65de6d21dec7371c589056c0a548e31624e121001e0020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010007361a1a0000000a000c000acaca11ec001d00170018fe0d00ba0000010001fc00206a2fb0535a0a5e565c8a61dcb381bab5636f1502bbd09fe491c66a2d175095370090dd4d770fc5e14f4a0e13cfd919a532d04c62eb4a53f67b1375bf237538cea180470d942bdde74611afe80d70ad25afb1d5f02b2b4eed784bc2420c759a742885f6ca982b25d0fdd7d8f618b7f7bc10172f61d446d8f8a6766f3587abbae805b8ef40fcb819194ac49e91c6c3762775f8dc269b82a21ddccc9f6f43be62323147b411475e47ea2c4efe52ef2cef5c7b32000d00120010040308040401050308050501080606010010000e000c02683208687474702f312e31000b0002010000050005010000000044cd00050003026832001b00030200020017000000230000002d000201010012000000000010000e00000b636861746770742e636f6d';
  return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

async function 带超时连接({ hostname, port }, ms) {
  const socket = connect({ hostname, port });
  await Promise.race([socket.opened, new Promise((_, r) => setTimeout(() => r("Timeout"), ms))]);
  return socket;
}

function 带超时读取(reader, ms) {
  return new Promise(res => {
    const t = setTimeout(() => res({ 超时: true }), ms);
    reader.read().then(v => { clearTimeout(t); res({ ...v, 超时: false }); });
  });
}

async function nginx() {
  return `<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Arial,sans-serif;}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed.</p></body></html>`;
}

// ================= UI 界面 =================
async function HTML(hostname, 网站图标, token) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Check ProxyIP</title>
  <link rel="icon" href="${网站图标}">
  <style>
    :root { --primary: #3498db; --bg: #f8f9fa; }
    body { font-family: 'Inter', sans-serif; background: linear-gradient(135deg, #667eea, #764ba2); min-height: 100vh; color: #2c3e50; margin: 0; padding: 20px; }
    .container { max-width: 800px; margin: 0 auto; }
    .card { background: white; border-radius: 12px; padding: 30px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
    .input-group { display: flex; gap: 10px; margin-top: 20px; }
    input { flex: 1; padding: 12px; border: 2px solid #ddd; border-radius: 6px; font-size: 16px; }
    button { padding: 12px 24px; background: var(--primary); color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }
    #result { margin-top: 20px; }
    .res-item { padding: 15px; border-radius: 8px; margin-bottom: 10px; border-left: 5px solid #ccc; background: #fefefe; }
    .success { border-color: #2ecc71; background: #eafaf1; }
    .error { border-color: #e74c3c; background: #fdedec; }
    .tag { padding: 2px 8px; background: #eee; border-radius: 4px; font-size: 12px; margin-right: 5px; }
  </style>
</head>
<body>
  <div class="container">
    <h1 style="color:white; text-align:center;">Check ProxyIP</h1>
    <div class="card">
      <div class="input-group">
        <input type="text" id="proxyip" placeholder="输入 IP:端口 或 域名" value="">
        <button onclick="doCheck()">立即检测</button>
      </div>
      <div id="result"></div>
    </div>
  </div>

  <script>
    // 自动填充上次搜索
    const last = localStorage.getItem('last_ip');
    if(last) document.getElementById('proxyip').value = last;

    async function doCheck() {
      const val = document.getElementById('proxyip').value.trim();
      if(!val) return;
      localStorage.setItem('last_ip', val);
      const resDiv = document.getElementById('result');
      resDiv.innerHTML = "正在检测中...";

      try {
        // 判断是域名还是IP
        const isIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?$/.test(val) || val.includes('[');
        
        if (isIP) {
          const r = await fetch(\`./check?proxyip=\${encodeURIComponent(val)}&token=${token}\`);
          const data = await r.json();
          renderResult(data);
        } else {
          const r = await fetch(\`./resolve?domain=\${encodeURIComponent(val)}&token=${token}\`);
          const data = await r.json();
          if(!data.success) throw new Error(data.error);
          resDiv.innerHTML = \`<p>域名解析出 \${data.ips.length} 个IP，开始逐个验证：</p>\`;
          for(const ip of data.ips) {
            const ir = await fetch(\`./check?proxyip=\${encodeURIComponent(ip)}&token=${token}\`);
            const idata = await ir.json();
            renderResult(idata, true);
          }
        }
      } catch(e) {
        resDiv.innerHTML = \`<div class="res-item error">检测失败: \${e.message}</div>\`;
      }
    }

    async function renderResult(data, append = false) {
      const resDiv = document.getElementById('result');
      if(!append) resDiv.innerHTML = "";
      
      let ipInfo = "";
      if(data.success) {
        try {
          const infoRes = await fetch(\`./ip-info?ip=\${data.proxyIP}&token=${token}\`);
          const info = await infoRes.json();
          ipInfo = \`<span class="tag">\${info.country || '未知'}</span><span class="tag">\${info.as || ''}</span>\`;
        } catch(e){}
      }

      const html = \`
        <div class="res-item \${data.success ? 'success' : 'error'}">
          <strong>\${data.proxyIP === -1 ? '连接失败' : data.proxyIP}</strong>
          <span style="float:right">\${data.responseTime > 0 ? data.responseTime + 'ms' : ''}</span>
          <br><small>\${data.message}</small>
          <div style="margin-top:5px;">\${ipInfo}</div>
        </div>
      \`;
      resDiv.innerHTML += html;
    }
  </script>
</body>
</html>`;
  return new Response(html, { headers: { "content-type": "text/html;charset=UTF-8" } });
}
