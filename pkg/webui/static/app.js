let ws = null;
let scanning = false;
let findings = [];
let chains = {};
let totalNodes = 0;
let doneNodes = 0;
let scanStartTime = null;
let elapsedTimer = null;
let sevCounts = { '严重': 0, '高危': 0, '中危': 0, '低危': 0, '信息': 0 };
const SEV_MAP = ['信息', '低危', '中危', '高危', '严重'];
const SEV_ICON = { '严重': '🔴', '高危': '🟠', '中危': '🟡', '低危': '🔵', '信息': '⚪' };

// 英文→中文翻译词典
const DICT = {
  // 常见描述片段
  'No auth required': '无需认证即可访问',
  'without auth': '无需认证',
  'accessible without authentication': '无需认证即可访问',
  'rate limiting': '速率限制',
  'no rate limiting': '无速率限制',
  'Rate limiting may be disabled': '速率限制可能已禁用',
  'rate limiting may be disabled entirely': '速率限制可能已完全禁用',
  'rapid requests without returning HTTP 429': '快速请求未返回 HTTP 429',
  'exposed': '暴露',
  'leaked': '泄露',
  'enumerable': '可枚举',
  'accessible': '可访问',
  'confirmed': '已确认',
  'detected': '已检测到',
  'vulnerable': '存在漏洞',
  'injection': '注入',
  'traversal': '遍历',
  'bypass': '绕过',
  'unauthorized': '未授权',
  'unauthenticated': '未认证',
  'disclosure': '信息泄露',
  'endpoint': '端点',
  'memory collections': '内存集合',
  'collection names': '集合名称',
  'attacker can discover': '攻击者可发现',
  'target specific': '针对特定',
  'agent/session memory stores': '代理/会话内存存储',
  'Platform identity': '平台身份信息',
  'error response': '错误响应',
  'unique endpoint signatures': '唯一端点签名',
  'Health endpoint exposes instance info': '健康检查端点暴露实例信息',
  'challenge gate active': '挑战门控已启用',
  'methods not enumerable': '方法不可枚举',
  'Pairing code entropy': '配对码熵值',
  'combinations': '种组合',
  'concurrent': '并发',
  'Code space': '码空间',
  'validation has no rate limiting': '验证无速率限制',
  'DM pairing code': 'DM 配对码',
  // 修复建议
  'Enable global rate limiting': '启用全局速率限制',
  'hard cap across all scopes': '对所有范围设置硬性上限',
  'Require authentication': '要求认证',
  'Restrict access': '限制访问',
  'Remove or restrict': '移除或限制',
  'Disable debug': '禁用调试',
  'Add authentication': '添加认证',
  'Implement rate limiting': '实施速率限制',
  'Use HTTPS': '使用 HTTPS',
  'Validate input': '验证输入',
  'Sanitize output': '净化输出',
  'Apply least privilege': '应用最小权限原则',
  'Rotate credentials': '轮换凭据',
  'Update to latest version': '更新到最新版本',
  'Patch immediately': '立即修补',
  'with a hard cap': '设置硬性上限',
};

function zhTranslate(text) {
  if (!text) return '';
  var result = text;
  // 按长度降序排列 key，避免短 key 先匹配破坏长 key
  var keys = Object.keys(DICT).sort(function(a, b) { return b.length - a.length; });
  for (var i = 0; i < keys.length; i++) {
    if (result.indexOf(keys[i]) >= 0) {
      result = result.split(keys[i]).join(DICT[keys[i]]);
    }
  }
  return result;
}

function connectWS() {
  var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(proto + '//' + location.host + '/ws');
  ws.onopen = function() { addLog('[*] 通信链路已建立', 'success'); };
  ws.onclose = function() {
    addLog('[!] 连接断开，3秒后重连...', 'warn');
    setTimeout(connectWS, 3000);
  };
  ws.onerror = function() {};
  ws.onmessage = function(e) {
    var msg = JSON.parse(e.data);
    switch (msg.type) {
      case 'progress': handleProgress(msg.data); break;
      case 'log': handleLog(msg.data); break;
      case 'finding': handleFinding(msg.data); break;
      case 'complete': handleComplete(msg.data); break;
      case 'error': handleError(msg.data); break;
      case 'status': handleStatus(msg.data); break;
    }
  };
}

function startScan() {
  var target = document.getElementById('target').value.trim();
  if (!target) { alert('请输入目标地址'); return; }
  fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target: target,
      token: document.getElementById('token').value.trim(),
      tls: document.getElementById('tls').checked,
      timeout: parseInt(document.getElementById('timeout').value) || 10,
      mode: document.getElementById('mode').value
    })
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (d.error) { addLog('[!] ' + d.error, 'error'); return; }
    scanning = true;
    findings = []; chains = {}; totalNodes = 0; doneNodes = 0;
    sevCounts = { '严重': 0, '高危': 0, '中危': 0, '低危': 0, '信息': 0 };
    document.getElementById('findings-body').innerHTML = '';
    document.getElementById('chain-list').innerHTML = '';
    document.getElementById('findings-empty').className = '';
    document.getElementById('btn-scan').disabled = true;
    document.getElementById('btn-cancel').disabled = false;
    document.getElementById('btn-export').disabled = true;
    document.getElementById('progress-bar').className = 'active';
    setBadge('扫描中', true);
    updateProgress(0, 0);
    updateStatus('scanning');
    scanStartTime = Date.now();
    elapsedTimer = setInterval(updateElapsed, 1000);
  });
}

function cancelScan() {
  fetch('/api/cancel', { method: 'POST' }).then(function(r) { return r.json(); }).then(function(d) {
    addLog('[!] ' + (d.message || '已取消'), 'warn');
  });
}

function exportReport() {
  window.open('/api/export?format=json', '_blank');
}

function handleProgress(data) {
  var id = data.task_id;
  if (!chains[id]) { chains[id] = { id: id, name: data.name, status: 'pending' }; totalNodes++; }
  var prev = chains[id].status;
  chains[id].status = data.status;
  if (data.elapsed) chains[id].elapsed = data.elapsed;
  if (prev !== 'done' && prev !== 'error' && prev !== 'skip') {
    if (data.status === 'done' || data.status === 'error' || data.status === 'skip') doneNodes++;
  }
  updateProgress(doneNodes, totalNodes);
  renderChains();
}

function handleLog(data) { addLog(data.message); }

function handleFinding(data) {
  findings.push(data);
  var sev = data.severity;
  var sevStr = (typeof sev === 'number') ? (SEV_MAP[sev] || '信息') : sev;
  if (sevCounts[sevStr] !== undefined) sevCounts[sevStr]++;
  document.getElementById('findings-empty').className = 'hidden';
  addFindingRow(data, sevStr);
  updateSevCounts();
}

function handleComplete(data) {
  scanning = false;
  clearInterval(elapsedTimer);
  document.getElementById('btn-scan').disabled = false;
  document.getElementById('btn-cancel').disabled = true;
  document.getElementById('progress-bar').className = '';
  if (findings.length > 0) document.getElementById('btn-export').disabled = false;
  updateProgress(totalNodes, totalNodes);
  updateStatus('idle');
  setBadge('完成', false);
  addLog('════════════════════════════════════════════', 'sep');
  var targetInfo = data.total_targets > 1 ? ' (' + data.total_targets + ' 个目标)' : '';
  if (findings.length > 0) {
    addLog('🔴 扫描完成 — 发现 ' + findings.length + ' 个安全问题！' + targetInfo + ' 耗时 ' + (data.elapsed || ''), 'error');
  } else {
    addLog('✅ 扫描完成 — 未发现安全问题。' + targetInfo + ' 耗时 ' + (data.elapsed || ''), 'success');
  }
  addLog('════════════════════════════════════════════', 'sep');
}

function handleError(data) {
  addLog('[!] 错误: ' + (data.message || JSON.stringify(data)), 'error');
  updateStatus('error');
  setBadge('错误', false);
}

function handleStatus(data) {
  if (data.scanning) {
    scanning = true;
    document.getElementById('btn-scan').disabled = true;
    document.getElementById('btn-cancel').disabled = false;
    updateStatus('scanning');
    setBadge('扫描中', true);
  }
  if (data.target) document.getElementById('target').value = data.target;
  if (data.token) document.getElementById('token').value = data.token;
}

function addLog(text, cls) {
  var el = document.getElementById('log-content');
  var line = document.createElement('div');
  if (!cls) {
    if (text.indexOf('[+]') >= 0) cls = 'success';
    else if (text.indexOf('[!]') >= 0) cls = 'error';
    else if (text.indexOf('[*]') >= 0) cls = 'dim';
    else if (text.charAt(0) === '═') cls = 'sep';
  }
  if (cls) line.className = 'log-' + cls;
  line.textContent = text;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
}

function addFindingRow(f, sevStr) {
  var tbody = document.getElementById('findings-body');
  var idx = findings.length;
  var tr = document.createElement('tr');
  var icon = SEV_ICON[sevStr] || '⚪';
  var title = zhTranslate(f.title || '');
  tr.innerHTML = '<td class="row-num">' + idx + '</td><td class="sev-' + sevStr + '">' + icon + ' ' + sevStr + '</td><td>' + esc(f.module || '') + '</td><td>' + esc(title) + '</td>';
  var detailTr = document.createElement('tr');
  var detailTd = document.createElement('td');
  detailTd.colSpan = 4;
  var detail = document.createElement('div');
  detail.className = 'finding-detail';
  var t = '';
  if (f.description) t += '📝 描述: ' + zhTranslate(f.description) + '\n';
  if (f.evidence) t += '🔍 证据: ' + zhTranslate(f.evidence) + '\n';
  if (f.remediation) t += '🛡️ 修复: ' + zhTranslate(f.remediation) + '\n';
  if (f.target) t += '🎯 目标: ' + f.target;
  detail.textContent = t;
  detailTd.appendChild(detail);
  detailTr.appendChild(detailTd);
  tr.onclick = function() { detail.classList.toggle('open'); };
  tbody.appendChild(tr);
  tbody.appendChild(detailTr);
  document.getElementById('findings-count').textContent = findings.length;
}

function renderChains() {
  var el = document.getElementById('chain-list');
  var sorted = Object.values(chains).sort(function(a, b) { return a.id - b.id; });
  el.innerHTML = sorted.map(function(c) {
    var icon = '○', cls = 'chain-pending';
    if (c.status === 'running') { icon = '▸'; cls = 'chain-running'; }
    else if (c.status === 'done') { icon = '✓'; cls = 'chain-done'; }
    else if (c.status === 'error') { icon = '✗'; cls = 'chain-error'; }
    else if (c.status === 'skip') { icon = '—'; cls = 'chain-skip'; }
    var elapsed = c.elapsed ? ' (' + fmtDur(c.elapsed) + ')' : '';
    return '<div class="chain-item ' + cls + '">' + icon + ' #' + String(c.id).padStart(2, '0') + ' ' + esc(c.name) + elapsed + '</div>';
  }).join('');
}

function updateProgress(done, total) {
  var pct = total > 0 ? Math.round(done / total * 100) : 0;
  document.getElementById('progress-bar').style.width = pct + '%';
  document.getElementById('progress-text').textContent = done + '/' + total + ' (' + pct + '%)';
}

function updateSevCounts() {
  document.getElementById('status-counts').textContent =
    '严重:' + sevCounts['严重'] + '  高危:' + sevCounts['高危'] +
    '  中危:' + sevCounts['中危'] + '  低危:' + sevCounts['低危'] + '  信息:' + sevCounts['信息'];
}

function updateStatus(state) {
  var el = document.getElementById('status-state');
  el.className = state;
  if (state === 'scanning') el.innerHTML = '<span class="dot-pulse"></span> 扫描中...';
  else if (state === 'error') el.textContent = '● 错误';
  else el.textContent = '● 就绪';
}

function updateElapsed() {
  if (!scanStartTime) return;
  var sec = Math.floor((Date.now() - scanStartTime) / 1000);
  var m = Math.floor(sec / 60), s = sec % 60;
  document.getElementById('status-elapsed').textContent = '耗时 ' + m + '分' + s + '秒';
}

function setBadge(text, active) {
  var el = document.getElementById('header-badge');
  el.textContent = text;
  el.className = active ? 'header-badge active' : 'header-badge';
}

function fmtDur(ns) {
  if (typeof ns === 'string') return ns;
  var ms = Math.round(ns / 1e6);
  if (ms < 1000) return ms + '毫秒';
  return (ms / 1000).toFixed(1) + '秒';
}

function esc(s) {
  var d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// Log panel resize
(function() {
  var handle = document.getElementById('log-resize-handle');
  var logPanel = document.getElementById('log-panel');
  var startY, startH;
  handle.addEventListener('mousedown', function(e) {
    startY = e.clientY; startH = logPanel.offsetHeight;
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
    e.preventDefault();
  });
  function onMove(e) {
    var h = startH + (startY - e.clientY);
    if (h >= 80 && h <= 600) logPanel.style.height = h + 'px';
  }
  function onUp() {
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
  }
})();

window.addEventListener('DOMContentLoaded', function() {
  connectWS();
  fetch('/api/status').then(function(r) { return r.json(); }).then(function(d) {
    if (d.target) document.getElementById('target').value = d.target;
    if (d.token) document.getElementById('token').value = d.token;
    if (d.tls) document.getElementById('tls').checked = true;
    if (d.timeout) document.getElementById('timeout').value = d.timeout;
  }).catch(function() {});
});
