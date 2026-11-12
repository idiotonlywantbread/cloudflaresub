// Cloudflare Worker: KV short link subscription + access token protection
// Requires:
// - KV namespace binding: SUB_STORE
// - Secret/Variable: SUB_ACCESS_TOKEN
// Optional:
// - Secret/Variable: SUB_LINK_SECRET (legacy long-token compatibility)

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
      'access-control-allow-headers': 'content-type, authorization',
    },
  });
}

function text(body, status = 200, contentType = 'text/plain; charset=utf-8') {
  return new Response(body, {
    status,
    headers: {
      'content-type': contentType,
      'access-control-allow-origin': '*',
    },
  });
}

function b64EncodeUtf8(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

function b64DecodeUtf8(str) {
  return decodeURIComponent(escape(atob(str)));
}

function escapeYaml(str = '') {
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, ' ');
}

function isValidIPv4(value) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) =>
    /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255
  );
}

function isValidDomain(value) {
  if (!value || value.length > 253 || value.includes('..')) return false;
  const domain = value.endsWith('.') ? value.slice(0, -1) : value;
  if (!domain) return false;
  return domain.split('.').every((label) =>
    label.length >= 1 &&
    label.length <= 63 &&
    /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label)
  );
}

function parsePreferredEndpoints(input) {
  const valid = [];
  const invalid = [];

  for (const originalLine of String(input || '').split(/\r?\n/)) {
    const line = originalLine.trim();
    if (!line) continue;

    const hashIndex = line.indexOf('#');
    const rawValue = (hashIndex >= 0 ? line.slice(0, hashIndex) : line).trim();
    const remark = hashIndex >= 0 ? line.slice(hashIndex + 1).trim() : '';

    let server = rawValue;
    let port;

    // 本功能按 IPv4 / 域名格式解析；不把 IPv6 的冒号误判为端口分隔符。
    const colonIndex = rawValue.lastIndexOf(':');
    if (colonIndex > 0 && rawValue.indexOf(':') === colonIndex) {
      const possiblePort = rawValue.slice(colonIndex + 1);
      if (/^\d+$/.test(possiblePort)) {
        server = rawValue.slice(0, colonIndex).trim();
        port = Number(possiblePort);
      } else {
        invalid.push({ line: originalLine, reason: '端口必须是 1-65535 的数字' });
        continue;
      }
    } else if (rawValue.includes(':')) {
      invalid.push({ line: originalLine, reason: '暂不支持 IPv6 或包含多个冒号的地址' });
      continue;
    }

    if (port !== undefined && (port < 1 || port > 65535)) {
      invalid.push({ line: originalLine, reason: '端口范围必须是 1-65535' });
      continue;
    }

    const isIp = isValidIPv4(server);
    const isDomain = isValidDomain(server);
    if (!isIp && !isDomain) {
      invalid.push({ line: originalLine, reason: '不是有效的 IPv4 或域名' });
      continue;
    }

    valid.push({
      server: server.toLowerCase(),
      port,
      remark,
    });
  }

  return { valid, invalid };
}

function endpointDedupKey(endpoint) {
  return `${endpoint.server.toLowerCase()}:${endpoint.port || ''}`;
}

function mergePreferredEndpoints(existing, incoming) {
  const result = [];
  const seen = new Set();

  for (const endpoint of [...existing, ...incoming]) {
    const key = endpointDedupKey(endpoint);
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(endpoint);
  }

  return result;
}

async function getStoredPreferredEndpoints(env) {
  const raw = await env.SUB_STORE.get('preferred:endpoints');
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

// 固定持久化列表使用独立 KV Key；通过独立清空接口管理，不影响普通列表。
async function getStoredPermanentPreferredEndpoints(env) {
  const raw = await env.SUB_STORE.get('preferred:permanent:endpoints');
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function isPermanentPreferredEnabled(env) {
  // 未设置时默认启用；设置为 false / 0 / no 可关闭固定列表参与订阅。
  const value = String(env.ENABLE_PERMANENT_PREFERRED ?? 'true').trim().toLowerCase();
  return !['false', '0', 'no', 'off', 'disabled'].includes(value);
}

function getCookie(request, name) {
  const cookie = request.headers.get('cookie') || '';
  for (const part of cookie.split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) {
      try { return decodeURIComponent(part.slice(index + 1).trim()); }
      catch { return ''; }
    }
  }
  return '';
}

function getRequestToken(request) {
  const authorization = request.headers.get('authorization') || '';
  const bearer = authorization.match(/^Bearer\s+(.+)$/i);
  return bearer?.[1] || getCookie(request, 'sub_auth') || '';
}

function validateApiToken(request, url, env) {
  const expected = env.SUB_ACCESS_TOKEN || '';
  if (!expected) {
    return { ok: false, response: json({ ok: false, error: '未配置 SUB_ACCESS_TOKEN' }, 503) };
  }

  const provided = getRequestToken(request);
  if (!provided || provided !== expected) {
    return { ok: false, response: json({ ok: false, error: 'Unauthorized: invalid token' }, 401) };
  }

  return { ok: true };
}

function isBrowserAuthenticated(request, env) {
  const expected = env.SUB_ACCESS_TOKEN || '';
  return Boolean(expected && getCookie(request, 'sub_auth') === expected);
}

function loginPage() {
  const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>个人订阅管理 - 身份验证</title><style>
  *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1220;color:#e5e7eb;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;padding:24px}.panel{width:min(420px,100%);padding:30px;border:1px solid #263247;border-radius:18px;background:#111c2e;box-shadow:0 20px 60px #0005}h1{font-size:23px;margin:0 0 8px}.muted{color:#9ca3af;font-size:14px;line-height:1.6}input{width:100%;margin:20px 0 12px;padding:14px;border:1px solid #37465e;border-radius:10px;background:#0b1220;color:#fff;font-size:16px}button{width:100%;padding:13px;border:0;border-radius:10px;background:#3b82f6;color:white;font-size:15px;font-weight:600;cursor:pointer}button:disabled{opacity:.6}.error{min-height:22px;color:#f87171;font-size:13px;margin-top:12px}
  </style></head><body><main class="panel"><h1>个人订阅管理</h1><p class="muted">请输入访问密钥。验证通过后才会加载管理页面。</p><form id="login"><input id="key" type="password" autocomplete="current-password" placeholder="访问密钥" required autofocus><button id="go" type="submit">验证并进入</button><div id="error" class="error" role="status"></div></form></main><script>
  const form=document.getElementById('login'),key=document.getElementById('key'),go=document.getElementById('go'),err=document.getElementById('error');
  form.addEventListener('submit',async e=>{e.preventDefault();err.textContent='';go.disabled=true;go.textContent='验证中...';try{const r=await fetch('/api/auth',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({token:key.value})});const d=await r.json().catch(()=>({}));if(!r.ok||!d.ok)throw new Error(d.error||'密钥错误');location.replace('/');}catch(x){err.textContent=x.message||'验证失败';key.focus();key.select();}finally{go.disabled=false;go.textContent='验证并进入';}});
  </script></body></html>`;
  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}

async function handleAuth(request, env) {
  const expected = env.SUB_ACCESS_TOKEN || '';
  if (!expected) return json({ ok: false, error: '服务端未配置 SUB_ACCESS_TOKEN' }, 503);
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: '请求格式错误' }, 400); }
  if (!body || typeof body.token !== 'string' || body.token !== expected) {
    return json({ ok: false, error: '访问密钥错误' }, 401);
  }
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'set-cookie': `sub_auth=${encodeURIComponent(expected)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800`,
    },
  });
}

// 登出不要求先通过认证：即使 Cookie 已损坏/过期，也始终尝试清除浏览器中的会话 Cookie。
function handleLogout() {
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'set-cookie': 'sub_auth=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0',
      'cache-control': 'no-store',
    },
  });
}

function parseVmess(link) {
  const raw = link.slice('vmess://'.length).trim();
  const obj = JSON.parse(b64DecodeUtf8(raw));
  return {
    type: 'vmess',
    name: obj.ps || 'vmess',
    server: obj.add,
    port: Number(obj.port || 443),
    uuid: obj.id,
    cipher: obj.scy || 'auto',
    network: obj.net || 'ws',
    tls: obj.tls === 'tls',
    host: obj.host || '',
    path: obj.path || '/',
    sni: obj.sni || obj.host || '',
    alpn: obj.alpn || '',
    fp: obj.fp || '',
  };
}

function parseUrlLike(link, type) {
  const u = new URL(link);
  return {
    type,
    name: decodeURIComponent(u.hash.replace(/^#/, '')) || type,
    server: u.hostname,
    port: Number(u.port || 443),
    password: type === 'trojan' ? decodeURIComponent(u.username) : undefined,
    uuid: type === 'vless' ? decodeURIComponent(u.username) : undefined,
    network: u.searchParams.get('type') || 'tcp',
    tls: (u.searchParams.get('security') || '').toLowerCase() === 'tls',
    host: u.searchParams.get('host') || u.searchParams.get('sni') || '',
    path: u.searchParams.get('path') || '/',
    sni: u.searchParams.get('sni') || u.searchParams.get('host') || '',
    fp: u.searchParams.get('fp') || '',
    alpn: u.searchParams.get('alpn') || '',
    flow: u.searchParams.get('flow') || '',
  };
}

function parseRawLinks(input) {
  const lines = String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const result = [];
  for (const line of lines) {
    if (line.startsWith('vmess://')) {
      result.push(parseVmess(line));
      continue;
    }
    if (line.startsWith('vless://')) {
      result.push(parseUrlLike(line, 'vless'));
      continue;
    }
    if (line.startsWith('trojan://')) {
      result.push(parseUrlLike(line, 'trojan'));
      continue;
    }
    try {
      const decoded = b64DecodeUtf8(line);
      if (/^(vmess|vless|trojan):\/\//m.test(decoded)) {
        result.push(...parseRawLinks(decoded));
      }
    } catch {}
  }
  return result;
}

function buildNodes(baseNodes, preferredEndpoints, options = {}) {
  const output = [];
  const prefix = (options.namePrefix || '').trim();
  let counter = 0;
  for (const node of baseNodes) {
    for (const ep of preferredEndpoints) {
      counter += 1;
      const nameParts = [];
      if (node.name) nameParts.push(node.name);
      if (prefix) nameParts.push(prefix);
      if (ep.remark) nameParts.push(ep.remark);
      else nameParts.push(String(counter));
      output.push({
        ...node,
        name: nameParts.join(' | '),
        server: ep.server,
        port: ep.port || node.port,
        host: options.keepOriginalHost ? node.host : '',
        sni: options.keepOriginalHost ? node.sni : '',
      });
    }
  }
  return output;
}

function encodeVmess(node) {
  const obj = {
    v: '2',
    ps: node.name,
    add: node.server,
    port: String(node.port),
    id: node.uuid,
    aid: '0',
    scy: node.cipher || 'auto',
    net: node.network || 'ws',
    type: 'none',
    host: node.host || '',
    path: node.path || '/',
    tls: node.tls ? 'tls' : '',
    sni: node.sni || '',
    alpn: node.alpn || '',
    fp: node.fp || '',
  };
  return 'vmess://' + b64EncodeUtf8(JSON.stringify(obj));
}

function encodeVless(node) {
  const url = new URL(`vless://${encodeURIComponent(node.uuid)}@${node.server}:${node.port}`);
  url.searchParams.set('type', node.network || 'ws');
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  if (node.flow) url.searchParams.set('flow', node.flow);
  url.hash = node.name;
  return url.toString();
}

function encodeTrojan(node) {
  const url = new URL(`trojan://${encodeURIComponent(node.password)}@${node.server}:${node.port}`);
  if (node.network) url.searchParams.set('type', node.network);
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  url.hash = node.name;
  return url.toString();
}

function renderRaw(nodes) {
  const lines = nodes
    .map((node) => {
      if (node.type === 'vmess') return encodeVmess(node);
      if (node.type === 'vless') return encodeVless(node);
      if (node.type === 'trojan') return encodeTrojan(node);
      return '';
    })
    .filter(Boolean);
  return b64EncodeUtf8(lines.join('\n'));
}

function renderClash(nodes) {
  const proxies = nodes
    .map((node) => {
      if (node.type === 'vmess') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: vmess`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    uuid: ${node.uuid}`,
          `    alterId: 0`,
          `    cipher: ${node.cipher || 'auto'}`,
          `    udp: true`,
          `    tls: ${node.tls ? 'true' : 'false'}`,
          `    network: ${node.network || 'ws'}`,
        ];

        if (node.sni) {
          lines.push(`    servername: "${escapeYaml(node.sni)}"`);
        }

        if ((node.network || 'ws') === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      if (node.type === 'vless') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: vless`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    uuid: ${node.uuid}`,
          `    udp: true`,
          `    tls: ${node.tls ? 'true' : 'false'}`,
          `    network: ${node.network || 'ws'}`,
        ];

        if (node.sni) {
          lines.push(`    servername: "${escapeYaml(node.sni)}"`);
        }

        if ((node.network || 'ws') === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      if (node.type === 'trojan') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: trojan`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    password: "${escapeYaml(node.password || '')}"`,
          `    udp: true`,
        ];

        if (node.sni) {
          lines.push(`    sni: "${escapeYaml(node.sni)}"`);
        }

        if (node.tls !== false) {
          lines.push(`    tls: true`);
        }

        if (node.network) {
          lines.push(`    network: ${node.network}`);
        }

        if (node.network === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      return '';
    })
    .filter(Boolean);

  const proxyNames = nodes.map(
    (node) => `      - "${escapeYaml(node.name)}"`
  );

  const allGroupMembers = [
    `      - "自动选择"`,
    ...proxyNames,
    `      - DIRECT`,
  ];

  const autoGroupMembers = proxyNames.length ? proxyNames : [`      - DIRECT`];

  return [
    `mixed-port: 7890`,
    `allow-lan: false`,
    `mode: rule`,
    `log-level: info`,
    `ipv6: true`,
    ``,
    `proxies:`,
    ...(proxies.length ? proxies : []),
    ``,
    `proxy-groups:`,
    `  - name: "自动选择"`,
    `    type: url-test`,
    `    url: "http://www.gstatic.com/generate_204"`,
    `    interval: 300`,
    `    tolerance: 50`,
    `    proxies:`,
    ...autoGroupMembers,
    ``,
    `  - name: "节点选择"`,
    `    type: select`,
    `    proxies:`,
    ...allGroupMembers,
    ``,
    `rules:`,
    `  - MATCH,节点选择`,
  ].join('\n');
}

function renderSurge(nodes, baseUrl, accessToken) {
  const proxies = nodes
    .filter((node) => node.type === 'vmess' || node.type === 'trojan')
    .map((node) => {
      if (node.type === 'vmess') {
        return `${node.name} = vmess, ${node.server}, ${node.port}, username=${node.uuid}, ws=true, ws-path=${node.path || '/'}, ws-headers=Host:${node.host || ''}, tls=${node.tls ? 'true' : 'false'}, sni=${node.sni || ''}`;
      }
      return `${node.name} = trojan, ${node.server}, ${node.port}, password=${node.password || ''}, sni=${node.sni || ''}`;
    });

  return [
    '[General]',
    'skip-proxy = 127.0.0.1, localhost',
    '',
    '[Proxy]',
    ...proxies,
    '',
    '[Proxy Group]',
    'Proxy = select, ' +
      nodes
        .filter((n) => n.type === 'vmess' || n.type === 'trojan')
        .map((n) => n.name)
        .join(', '),
    '',
    '[Rule]',
    'FINAL,Proxy',
    '',
    '; token-protected subscription',
    `; ${baseUrl}?token=${accessToken}`,
  ].join('\n');
}

function createShortId(length = 10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = '';
  for (let i = 0; i < length; i++) {
    out += chars[bytes[i] % chars.length];
  }
  return out;
}

async function createUniqueShortId(env, tries = 8) {
  for (let i = 0; i < tries; i++) {
    const id = createShortId(10);
    const exists = await env.SUB_STORE.get(`sub:${id}`);
    if (!exists) return id;
  }
  throw new Error('无法生成唯一短链接，请稍后再试');
}

function normalizeLines(value = '') {
  return String(value)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .sort()
    .join('\n');
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function buildDedupHash(body, preferredEndpoints = []) {
  const normalized = {
    nodeLinks: normalizeLines(body.nodeLinks || ''),
    preferredIps: normalizeLines(body.preferredIps || ''),
    effectivePreferredEndpoints: preferredEndpoints.map((ep) => `${endpointDedupKey(ep)}#${ep.remark || ''}`).sort(),
    namePrefix: String(body.namePrefix || '').trim(),
    keepOriginalHost: body.keepOriginalHost !== false,
  };
  return sha256Hex(JSON.stringify(normalized));
}

async function handleGenerate(request, env, url) {
  const auth = validateApiToken(request, url, env);
  if (!auth.ok) return auth.response;

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: '请求体不是合法 JSON' }, 400);
  }

  const baseNodes = parseRawLinks(body.nodeLinks || '');
  const parsedPreferred = parsePreferredEndpoints(body.preferredIps || '');
  const normalStored = await getStoredPreferredEndpoints(env);
  const permanentStored = isPermanentPreferredEnabled(env)
    ? await getStoredPermanentPreferredEndpoints(env)
    : [];
  // 生成时合并：页面本次输入 + 普通 KV 列表（第 2 项）+ 固定 KV 列表（第 3 项），按地址去重。
  const preferredEndpoints = mergePreferredEndpoints(
    mergePreferredEndpoints(normalStored, parsedPreferred.valid),
    permanentStored,
  );

  if (!baseNodes.length) return json({ ok: false, error: '没有识别到可用节点' }, 400);
  if (!preferredEndpoints.length) {
    return json({
      ok: false,
      error: '第 2 项普通列表和第 3 项固定列表均没有可用地址，请先保存或上传优选地址',
      invalid: parsedPreferred.invalid,
    }, 400);
  }

  const options = {
    namePrefix: body.namePrefix || '',
    keepOriginalHost: body.keepOriginalHost !== false,
  };

  const nodes = buildNodes(baseNodes, preferredEndpoints, options);

  const payload = {
    version: 1,
    createdAt: new Date().toISOString(),
    options,
    nodes,
  };

  // 配置 FIXED_SUB_ID 后，所有生成操作都覆盖同一个 KV 记录，短链接永久固定。
  // 固定模式不设置 TTL，也不走内容哈希去重；更新配置即更新同一条订阅。
  const configuredFixedId = String(env.FIXED_SUB_ID || '').trim();
  let id;
  let fixedLink = false;

  if (configuredFixedId) {
    if (!/^[A-Za-z0-9_-]{3,64}$/.test(configuredFixedId)) {
      return json({ ok: false, error: 'FIXED_SUB_ID 格式无效，只允许 3-64 位字母、数字、下划线和连字符' }, 503);
    }
    id = configuredFixedId;
    fixedLink = true;
    await env.SUB_STORE.put(`sub:${id}`, JSON.stringify(payload));
  } else {
    const dedupHash = await buildDedupHash(body, preferredEndpoints);
    const dedupKey = `dedup:${dedupHash}`;
    id = await env.SUB_STORE.get(dedupKey);

    if (!id) {
      id = await createUniqueShortId(env);
      const ttl = 60 * 60 * 24 * 7; // 普通模式保留 7 天
      await env.SUB_STORE.put(`sub:${id}`, JSON.stringify(payload), { expirationTtl: ttl });
      await env.SUB_STORE.put(dedupKey, id, { expirationTtl: ttl });
    }
  }

  const origin = url.origin;
  const accessToken = env.SUB_ACCESS_TOKEN || '';
  const withToken = (target) =>
    `${origin}/sub/${id}${
      target
        ? `?target=${target}&token=${encodeURIComponent(accessToken)}`
        : `?token=${encodeURIComponent(accessToken)}`
    }`;

  return json({
    ok: true,
    storage: 'kv',
    deduplicated: !fixedLink,
    fixedLink,
    shortId: id,
    urls: {
      auto: withToken(''),
      raw: withToken('raw'),
      clash: withToken('clash'),
      surge: withToken('surge'),
    },
    counts: {
      inputNodes: baseNodes.length,
      preferredEndpoints: preferredEndpoints.length,
      outputNodes: nodes.length,
    },
    preview: nodes.slice(0, 20).map((node) => ({
      name: node.name,
      type: node.type,
      server: node.server,
      port: node.port,
      host: node.host || '',
      sni: node.sni || '',
    })),
    warnings: fixedLink ? ['固定短链接模式：后续生成会覆盖同一链接对应的订阅内容。'] : ['未设置 FIXED_SUB_ID：当前使用临时短链接，7 天后过期。'],
  });
}

function validateAccessToken(url, env) {
  const expected = env.SUB_ACCESS_TOKEN || '';
  if (!expected) return { ok: false, response: text('Service unavailable: SUB_ACCESS_TOKEN is not configured', 503) };
  const provided = url.searchParams.get('token') || '';
  if (!provided || provided !== expected) {
    return { ok: false, response: text('Forbidden: invalid token', 403) };
  }
  return { ok: true };
}

async function handlePreferredGet(request, env, url) {
  const auth = validateApiToken(request, url, env);
  if (!auth.ok) return auth.response;

  const endpoints = await getStoredPreferredEndpoints(env);
  const content = endpoints.map((ep) =>
    `${ep.server}${ep.port ? `:${ep.port}` : ''}${ep.remark ? `#${ep.remark}` : ''}`
  ).join('\n');

  return json({
    ok: true,
    count: endpoints.length,
    content,
    endpoints,
  });
}

async function handlePreferredAppend(request, env, url) {
  const auth = validateApiToken(request, url, env);
  if (!auth.ok) return auth.response;

  let input = '';
  const contentType = request.headers.get('content-type') || '';

  if (contentType.includes('application/json')) {
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ ok: false, error: '请求体不是合法 JSON' }, 400);
    }
    input = body.content ?? body.preferredIps ?? body.text ?? '';
  } else {
    input = await request.text();
  }

  const parsed = parsePreferredEndpoints(input);
  if (!parsed.valid.length) {
    return json({
      ok: false,
      error: '没有可保存的有效优选地址',
      added: 0,
      invalid: parsed.invalid,
    }, 400);
  }

  const existing = await getStoredPreferredEndpoints(env);
  const merged = mergePreferredEndpoints(existing, parsed.valid);
  const added = merged.length - existing.length;

  // 不设置 expirationTtl：优选地址长期保存在 KV，直到主动清空。
  await env.SUB_STORE.put('preferred:endpoints', JSON.stringify(merged));

  return json({
    ok: true,
    mode: 'append',
    received: parsed.valid.length,
    added,
    duplicates: parsed.valid.length - added,
    invalidCount: parsed.invalid.length,
    total: merged.length,
    invalid: parsed.invalid,
  });
}

async function handlePermanentPreferredGet(request, env, url) {
  const auth = validateApiToken(request, url, env);
  if (!auth.ok) return auth.response;

  const endpoints = await getStoredPermanentPreferredEndpoints(env);
  const content = endpoints.map((ep) =>
    `${ep.server}${ep.port ? `:${ep.port}` : ''}${ep.remark ? `#${ep.remark}` : ''}`
  ).join('\n');

  return json({
    ok: true,
    count: endpoints.length,
    content,
    enabled: isPermanentPreferredEnabled(env),
    deletableByApi: false,
  });
}

async function handlePermanentPreferredAppend(request, env, url) {
  const auth = validateApiToken(request, url, env);
  if (!auth.ok) return auth.response;

  let input = '';
  const contentType = request.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ ok: false, error: '请求体不是合法 JSON' }, 400);
    }
    input = body.content ?? body.preferredIps ?? body.text ?? '';
  } else {
    input = await request.text();
  }

  const parsed = parsePreferredEndpoints(input);
  if (!parsed.valid.length) {
    return json({ ok: false, error: '没有可追加到固定列表的有效地址', invalid: parsed.invalid }, 400);
  }

  const existing = await getStoredPermanentPreferredEndpoints(env);
  const merged = mergePreferredEndpoints(existing, parsed.valid);
  const added = merged.length - existing.length;
  // 追加保存，不设置 TTL；清空由独立接口执行。
  await env.SUB_STORE.put('preferred:permanent:endpoints', JSON.stringify(merged));

  return json({
    ok: true,
    mode: 'append-only',
    received: parsed.valid.length,
    added,
    duplicates: parsed.valid.length - added,
    invalidCount: parsed.invalid.length,
    total: merged.length,
    enabled: isPermanentPreferredEnabled(env),
    invalid: parsed.invalid,
  });
}

async function handlePermanentPreferredClear(request, env, url) {
  const auth = validateApiToken(request, url, env);
  if (!auth.ok) return auth.response;

  const before = await getStoredPermanentPreferredEndpoints(env);
  await env.SUB_STORE.delete('preferred:permanent:endpoints');

  return json({
    ok: true,
    cleared: before.length,
    total: 0,
  });
}

async function handlePreferredClear(request, env, url) {
  const auth = validateApiToken(request, url, env);
  if (!auth.ok) return auth.response;

  const before = await getStoredPreferredEndpoints(env);
  await env.SUB_STORE.delete('preferred:endpoints');

  return json({
    ok: true,
    cleared: before.length,
    total: 0,
  });
}

async function handleSub(url, env) {
  const tokenCheck = validateAccessToken(url, env);
  if (!tokenCheck.ok) return tokenCheck.response;

  const id = url.pathname.split('/').pop();
  if (!id) return text('missing id', 400);

  const raw = await env.SUB_STORE.get(`sub:${id}`);
  if (!raw) return text('not found', 404);

  const record = JSON.parse(raw);
  const nodes = record.nodes || [];
  const target = (url.searchParams.get('target') || 'raw').toLowerCase();

  if (target === 'clash') {
    return text(renderClash(nodes), 200, 'text/yaml; charset=utf-8');
  }
  if (target === 'surge') {
    return text(
      renderSurge(nodes, url.origin + url.pathname, env.SUB_ACCESS_TOKEN || ''),
      200,
      'text/plain; charset=utf-8',
    );
  }
  return text(renderRaw(nodes), 200, 'text/plain; charset=utf-8');
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET,POST,OPTIONS',
          'access-control-allow-headers': 'content-type, authorization',
        },
      });
    }

    if (request.method === 'POST' && url.pathname === '/api/auth') {
      return handleAuth(request, env);
    }

    if (request.method === 'POST' && url.pathname === '/api/logout') {
      return handleLogout();
    }

    if (request.method === 'POST' && url.pathname === '/api/generate') {
      return handleGenerate(request, env, url);
    }

    if (request.method === 'GET' && url.pathname === '/api/preferred') {
      return handlePreferredGet(request, env, url);
    }

    if (request.method === 'POST' &&
        (url.pathname === '/api/preferred/save' || url.pathname === '/api/preferred/upload')) {
      return handlePreferredAppend(request, env, url);
    }

    if (request.method === 'POST' && url.pathname === '/api/preferred/clear') {
      return handlePreferredClear(request, env, url);
    }

    if (request.method === 'GET' && url.pathname === '/api/permanent-preferred') {
      return handlePermanentPreferredGet(request, env, url);
    }

    if (request.method === 'POST' && url.pathname === '/api/permanent-preferred/save') {
      return handlePermanentPreferredAppend(request, env, url);
    }

    if (request.method === 'POST' && url.pathname === '/api/permanent-preferred/clear') {
      return handlePermanentPreferredClear(request, env, url);
    }

    if (request.method === 'GET' && url.pathname.startsWith('/sub/')) {
      return handleSub(url, env);
    }

    // API 仅允许同源浏览器请求；命令行客户端不带 Origin 时仍可用 Bearer Token。
    const requestOrigin = request.headers.get('origin');
    if (url.pathname.startsWith('/api/') && requestOrigin && requestOrigin !== url.origin) {
      return json({ ok: false, error: 'Cross-origin API requests are not allowed' }, 403);
    }

    // 静态管理页面、JS、CSS、图标全部受登录 Cookie 保护。
    if (isBrowserAuthenticated(request, env)) {
      const assetResponse = await env.ASSETS.fetch(request);
      const headers = new Headers(assetResponse.headers);
      headers.set('cache-control', 'no-store');
      return new Response(assetResponse.body, { status: assetResponse.status, statusText: assetResponse.statusText, headers });
    }

    if (url.pathname === '/' || url.pathname === '/index.html') {
      return loginPage();
    }
    return text('Unauthorized', 401);
  },
};
