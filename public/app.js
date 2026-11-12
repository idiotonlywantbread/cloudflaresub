const form = document.getElementById('generator-form');
const submitBtn = document.getElementById('submitBtn');
const fillDemoBtn = document.getElementById('fillDemoBtn');
const resultSection = document.getElementById('resultSection');
const warningBox = document.getElementById('warningBox');
const previewBody = document.getElementById('previewBody');

const preferredIps = document.getElementById('preferredIps');
const preferredToken = document.getElementById('preferredToken');
const savePreferredBtn = document.getElementById('savePreferredBtn');
const clearPreferredBtn = document.getElementById('clearPreferredBtn');
const preferredStatus = document.getElementById('preferredStatus');
const permanentPreferredIps = document.getElementById('permanentPreferredIps');
const savePermanentPreferredBtn = document.getElementById('savePermanentPreferredBtn');
const permanentPreferredStatus = document.getElementById('permanentPreferredStatus');

const autoUrl = document.getElementById('autoUrl');
const rawUrl = document.getElementById('rawUrl');
const clashUrl = document.getElementById('clashUrl');
const surgeUrl = document.getElementById('surgeUrl');
const emptyState = document.getElementById('emptyState');

const qrModal = document.getElementById('qrModal');
const qrCanvas = document.getElementById('qrCanvas');
const qrText = document.getElementById('qrText');
const closeQrModal = document.getElementById('closeQrModal');

const demoVmess = [
  'vmess://ewogICJ2IjogIjIiLAogICJwcyI6ICJkZW1vLXdzLXRscyIsCiAgImFkZCI6ICJlZGdlLmV4YW1wbGUuY29tIiwKICAicG9ydCI6ICI0NDMiLAogICJpZCI6ICIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLAogICJzY3kiOiAiYXV0byIsCiAgIm5ldCI6ICJ3cyIsCiAgInRscyI6ICJ0bHMiLAogICJwYXRoIjogIi93cyIsCiAgImhvc3QiOiAiZWRnZS5leGFtcGxlLmNvbSIsCiAgInNuaSI6ICJlZGdlLmV4YW1wbGUuY29tIiwKICAiZnAiOiAiY2hyb21lIiwKICAiYWxwbiI6ICJoMixodHRwLzEuMSIKfQ=='
].join('\n');

const demoIps = [
  '104.16.1.2#HK-01',
  '104.17.2.3#HK-02',
  '104.18.3.4:2053#US-Edge'
].join('\n');

// Token 仅保存在当前标签页会话中，不写入 localStorage，也不硬编码到前端。
const TOKEN_SESSION_KEY = 'preferred_api_token';
preferredToken.value = sessionStorage.getItem(TOKEN_SESSION_KEY) || '';

preferredToken.addEventListener('input', () => {
  const token = preferredToken.value.trim();
  if (token) sessionStorage.setItem(TOKEN_SESSION_KEY, token);
  else sessionStorage.removeItem(TOKEN_SESSION_KEY);
});

function getApiHeaders(json = false) {
  const token = preferredToken.value.trim();
  if (!token) throw new Error('请先填写现有 SUB_ACCESS_TOKEN。');
  const headers = { Authorization: `Bearer ${token}` };
  if (json) headers['content-type'] = 'application/json';
  return headers;
}

async function preferredApi(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...getApiHeaders(Boolean(options.jsonBody)),
      ...(options.headers || {}),
    },
    body: options.jsonBody ? JSON.stringify(options.jsonBody) : options.body,
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.ok) {
    throw new Error(data.error || `API 请求失败（HTTP ${response.status}）`);
  }
  return data;
}

function setPreferredStatus(message, isError = false) {
  preferredStatus.textContent = message;
  preferredStatus.style.color = isError ? '#dc2626' : '';
}

function setPermanentPreferredStatus(message, isError = false) {
  permanentPreferredStatus.textContent = message;
  permanentPreferredStatus.style.color = isError ? '#dc2626' : '';
}

async function loadPermanentPreferredEndpoints(showMessage = false) {
  try {
    const data = await preferredApi('/api/permanent-preferred', { method: 'GET' });
    permanentPreferredIps.value = data.content || '';
    setPermanentPreferredStatus(`已加载 ${data.count} 条固定地址；${data.enabled ? '参与订阅生成' : '当前已关闭参与生成'}`);
    return true;
  } catch (error) {
    if (showMessage) setPermanentPreferredStatus(error.message, true);
    else setPermanentPreferredStatus('填写 Token 后自动加载固定列表');
    return false;
  }
}

savePermanentPreferredBtn.addEventListener('click', async () => {
  const content = permanentPreferredIps.value.trim();
  if (!content) {
    setPermanentPreferredStatus('固定列表输入框为空，没有可追加的内容。', true);
    return;
  }

  savePermanentPreferredBtn.disabled = true;
  const originalText = savePermanentPreferredBtn.textContent;
  savePermanentPreferredBtn.textContent = '追加中...';
  try {
    const data = await preferredApi('/api/permanent-preferred/save', {
      method: 'POST',
      jsonBody: { content },
    });
    await loadPermanentPreferredEndpoints();
    setPermanentPreferredStatus(`追加完成：新增 ${data.added} 条，重复 ${data.duplicates} 条，无效 ${data.invalidCount} 条；固定列表共 ${data.total} 条`);
  } catch (error) {
    setPermanentPreferredStatus(error.message, true);
  } finally {
    savePermanentPreferredBtn.disabled = false;
    savePermanentPreferredBtn.textContent = originalText;
  }
});

async function loadPreferredEndpoints(showMessage = false) {
  try {
    const data = await preferredApi('/api/preferred', { method: 'GET' });
    preferredIps.value = data.content || '';
    setPreferredStatus(`已加载 ${data.count} 条已保存地址`);
    return true;
  } catch (error) {
    if (showMessage) setPreferredStatus(error.message, true);
    else setPreferredStatus('填写 Token 后自动加载已保存地址');
    return false;
  }
}

savePreferredBtn.addEventListener('click', async () => {
  const content = preferredIps.value.trim();
  if (!content) {
    setPreferredStatus('输入框为空，没有可追加保存的内容。', true);
    return;
  }

  savePreferredBtn.disabled = true;
  const originalText = savePreferredBtn.textContent;
  savePreferredBtn.textContent = '保存中...';

  try {
    const data = await preferredApi('/api/preferred/save', {
      method: 'POST',
      jsonBody: { content },
    });
    await loadPreferredEndpoints();
    setPreferredStatus(
      `保存完成：新增 ${data.added} 条，重复 ${data.duplicates} 条，无效 ${data.invalidCount} 条；总计 ${data.total} 条`
    );
  } catch (error) {
    setPreferredStatus(error.message, true);
  } finally {
    savePreferredBtn.disabled = false;
    savePreferredBtn.textContent = originalText;
  }
});

clearPreferredBtn.addEventListener('click', async () => {
  if (!window.confirm('确定清空 KV 中保存的全部优选 IP / 域名吗？此操作不可撤销。')) return;

  clearPreferredBtn.disabled = true;
  const originalText = clearPreferredBtn.textContent;
  clearPreferredBtn.textContent = '清空中...';

  try {
    const data = await preferredApi('/api/preferred/clear', { method: 'POST' });
    preferredIps.value = '';
    setPreferredStatus(`已清空 ${data.cleared} 条优选地址`);
  } catch (error) {
    setPreferredStatus(error.message, true);
  } finally {
    clearPreferredBtn.disabled = false;
    clearPreferredBtn.textContent = originalText;
  }
});

preferredToken.addEventListener('change', () => {
  loadPreferredEndpoints(true);
  loadPermanentPreferredEndpoints(true);
});

fillDemoBtn.addEventListener('click', () => {
  document.getElementById('nodeLinks').value = demoVmess;
  preferredIps.value = demoIps;
  document.getElementById('namePrefix').value = 'CF';
  document.getElementById('keepOriginalHost').checked = true;
  setPreferredStatus('已填入演示地址；点击“保存优选地址”可追加到 KV。');
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  warningBox.classList.add('hidden');
  previewBody.innerHTML = '';

  const payload = {
    nodeLinks: document.getElementById('nodeLinks').value,
    preferredIps: preferredIps.value,
    namePrefix: document.getElementById('namePrefix').value,
    keepOriginalHost: document.getElementById('keepOriginalHost').checked,
  };

  submitBtn.disabled = true;
  submitBtn.textContent = '生成中...';

  try {
    const response = await fetch('/api/generate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    if (!response.ok || !data.ok) {
      const invalidText = Array.isArray(data.invalid) && data.invalid.length
        ? '\n无效地址：\n' + data.invalid.map((item) => `${item.line}（${item.reason}）`).join('\n')
        : '';
      throw new Error((data.error || '生成失败') + invalidText);
    }

    autoUrl.value = data.urls.auto;
    rawUrl.value = data.urls.raw;
    document.getElementById('rocketUrl').value = data.urls.raw;
    clashUrl.value = data.urls.clash;
    surgeUrl.value = data.urls.surge;

    emptyState.classList.add('hidden');
    document.getElementById('statInputNodes').textContent = data.counts.inputNodes;
    document.getElementById('statEndpoints').textContent = data.counts.preferredEndpoints;
    document.getElementById('statOutputNodes').textContent = data.counts.outputNodes;

    previewBody.innerHTML = data.preview.map((item) => `
      <tr>
        <td>${escapeHtml(item.name)}</td>
        <td>${escapeHtml(item.type)}</td>
        <td>${escapeHtml(item.server)}</td>
        <td>${escapeHtml(String(item.port))}</td>
        <td>${escapeHtml(item.host || '-')}</td>
        <td>${escapeHtml(item.sni || '-')}</td>
      </tr>
    `).join('');

    if (Array.isArray(data.warnings) && data.warnings.length) {
      warningBox.textContent = data.warnings.join('\n');
      warningBox.classList.remove('hidden');
    }

    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) {
    warningBox.textContent = error.message || '请求失败';
    warningBox.classList.remove('hidden');
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = '生成订阅';
  }
});

document.addEventListener('click', async (event) => {
  const copyButton = event.target.closest('[data-copy-target]');
  if (copyButton) {
    const input = document.getElementById(copyButton.dataset.copyTarget);
    if (!input?.value) return;
    try {
      await navigator.clipboard.writeText(input.value);
      const originalText = copyButton.textContent;
      copyButton.textContent = '已复制';
      setTimeout(() => { copyButton.textContent = originalText; }, 1200);
    } catch {
      input.select();
      document.execCommand('copy');
    }
    return;
  }

  const qrButton = event.target.closest('[data-qrcode-target]');
  if (qrButton) {
    warningBox.classList.add('hidden');
    const input = document.getElementById(qrButton.dataset.qrcodeTarget);
    if (!input?.value) {
      warningBox.textContent = '请先生成订阅链接，再显示二维码。';
      warningBox.classList.remove('hidden');
      return;
    }
    if (!window.QRCode) {
      warningBox.textContent = '二维码组件加载失败，请刷新页面后重试。';
      warningBox.classList.remove('hidden');
      return;
    }

    qrCanvas.innerHTML = '';
    qrText.textContent = input.value;
    qrModal.classList.remove('hidden');
    qrModal.setAttribute('aria-hidden', 'false');
    new window.QRCode(qrCanvas, {
      text: input.value,
      width: 220,
      height: 220,
      correctLevel: window.QRCode.CorrectLevel.M,
    });
    return;
  }

  if (event.target.closest('[data-close-modal="true"]')) closeQrDialog();
});

closeQrModal.addEventListener('click', closeQrDialog);

function closeQrDialog() {
  qrModal.classList.add('hidden');
  qrModal.setAttribute('aria-hidden', 'true');
  qrCanvas.innerHTML = '';
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

// 页面打开时尝试读取 KV；如尚未填写 Token，会提示先填写。
if (preferredToken.value) {
  loadPreferredEndpoints();
  loadPermanentPreferredEndpoints();
} else {
  setPreferredStatus('填写 Token 后自动加载已保存地址');
  setPermanentPreferredStatus('填写 Token 后自动加载固定列表');
}
