/**
 * 烽火CPE状态小组件 - Egern Widget
 *
 * 环境变量:
 *   CPE_HOST: CPE管理地址，默认 192.168.8.1
 *   CPE_USER: 登录用户名，默认 useradmin
 *   CPE_PASS: 登录密码，默认 空
 *
 * 登录机制: IP级会话 — AES-128-ECB 加密POST
 *   key  = sessionid前16字节 (UTF-8)
 *   body = <6字符随机前缀> + hex(AES_ECB_PKCS7(payload))
 */

// ==================== 配置 ====================

function getConfig(ctx) {
  return {
    host: ctx.env.CPE_HOST || '192.168.8.1',
    user: ctx.env.CPE_USER || 'useradmin',
    pass: ctx.env.CPE_PASS || '',
  };
}

// ==================== 极简 AES-128-ECB ====================
// 仅需 encrypt，不需 decrypt

const SBOX = [
  99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,
  202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,
  183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,
  4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,
  9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,
  83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,
  208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,
  81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,
  205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,
  96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,
  224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,
  231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,
  186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,
  112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,
  225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,
  140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22,
];

const RCON = [0,1,2,4,8,16,32,64,128,27,54];

function subBytes(s) { return s.map(b => SBOX[b]); }
function rotWord(w) { return [w[1],w[2],w[3],w[0]]; }
function subWord(w) { return w.map(b => SBOX[b]); }
function xorWords(a, b) { return a.map((v,i) => v ^ b[i]); }

function gmul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hiBit = a & 0x80;
    a = (a << 1) & 0xff;
    if (hiBit) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

function shiftRows(s) {
  // s is 4x4 col-major: s[col*4+row]
  const t = s.slice();
  // row 1: shift left 1
  t[1]=s[5]; t[5]=s[9]; t[9]=s[13]; t[13]=s[1];
  // row 2: shift left 2
  t[2]=s[10]; t[10]=s[2]; t[6]=s[14]; t[14]=s[6];
  // row 3: shift left 3
  t[3]=s[15]; t[7]=s[3]; t[11]=s[7]; t[15]=s[11];
  return t;
}

function mixColumns(s) {
  const t = s.slice();
  for (let c = 0; c < 4; c++) {
    const i = c * 4;
    const [a,b,d,e] = [s[i],s[i+1],s[i+2],s[i+3]];
    t[i]   = gmul(a,2)^gmul(b,3)^d^e;
    t[i+1] = a^gmul(b,2)^gmul(d,3)^e;
    t[i+2] = a^b^gmul(d,2)^gmul(e,3);
    t[i+3] = gmul(a,3)^b^d^gmul(e,2);
  }
  return t;
}

function addRoundKey(state, w, round) {
  return state.map((b, i) => b ^ w[round*16 + i]);
}

function keyExpansion(key) {
  // key: 16-byte array, returns 176-byte round keys
  const w = key.slice();
  for (let i = 4; i < 44; i++) {
    let temp = w.slice((i-1)*4, i*4);
    if (i % 4 === 0) {
      temp = xorWords(subWord(rotWord(temp)), [RCON[i/4],0,0,0]);
    }
    const prev = w.slice((i-4)*4, (i-3)*4);
    w.push(...xorWords(temp, prev));
  }
  return w;
}

function bytesToState(block) {
  // col-major order
  const s = new Array(16);
  for (let c = 0; c < 4; c++)
    for (let r = 0; r < 4; r++)
      s[c*4+r] = block[r*4+c];
  return s;
}

function stateToBytes(s) {
  const b = new Array(16);
  for (let c = 0; c < 4; c++)
    for (let r = 0; r < 4; r++)
      b[r*4+c] = s[c*4+r];
  return b;
}

function aes128EncryptBlock(block16, roundKeys) {
  let state = bytesToState(block16);
  state = addRoundKey(state, roundKeys, 0);
  for (let r = 1; r <= 10; r++) {
    state = subBytes(state);
    state = shiftRows(state);
    if (r < 10) state = mixColumns(state);
    state = addRoundKey(state, roundKeys, r);
  }
  return stateToBytes(state);
}

/** AES-128-ECB-PKCS7 encrypt, returns hex string */
function aesEcbEncryptHex(plaintext, keyStr) {
  // UTF-8 encode
  const enc = s => Array.from(new TextEncoder().encode(s));
  const data = enc(plaintext);
  // PKCS7 pad
  const pad = 16 - (data.length % 16);
  const padded = [...data, ...new Array(pad).fill(pad)];
  // key bytes (first 16)
  const keyBytes = enc(keyStr).slice(0, 16);
  const rk = keyExpansion(keyBytes);
  // encrypt each block
  let hex = '';
  for (let i = 0; i < padded.length; i += 16) {
    const block = padded.slice(i, i + 16);
    const enc16 = aes128EncryptBlock(block, rk);
    hex += enc16.map(b => b.toString(16).padStart(2, '0')).join('');
  }
  return hex;
}

// ==================== 随机前缀生成 ====================
// 格式: 6字符，其中3个来自 g-z（模拟观察到的格式）

function randomPrefix() {
  const hex = '0123456789abcdef';
  const ext = 'ghijklmnopqrstuvwxyz';
  const chars = [];
  const extPositions = new Set();
  while (extPositions.size < 3) extPositions.add(Math.floor(Math.random() * 6));
  for (let i = 0; i < 6; i++) {
    if (extPositions.has(i)) {
      chars.push(ext[Math.floor(Math.random() * ext.length)]);
    } else {
      chars.push(hex[Math.floor(Math.random() * hex.length)]);
    }
  }
  return chars.join('');
}

// ==================== 网络请求 ====================

const BASE_HEADERS = {
  'X-Requested-With': 'XMLHttpRequest',
  'Referer': 'http://{{HOST}}/main.html',
};

function makeHeaders(host, extra = {}) {
  return {
    ...BASE_HEADERS,
    'Referer': `http://${host}/main.html`,
    ...extra,
  };
}

async function fhGet(ctx, cfg, endpoint, ajaxmethod) {
  const resp = await ctx.http.get(
    `http://${cfg.host}/fh_api/tmp/${endpoint}?ajaxmethod=${ajaxmethod}`,
    { headers: makeHeaders(cfg.host) }
  );
  const text = await resp.text();
  // 若返回HTML(被重定向到登录页)则抛出明确错误
  if (text.trim().startsWith('<')) throw new Error('需要登录: 收到HTML响应');
  return JSON.parse(text);
}

// ==================== 登录 ====================

async function login(ctx, cfg) {
  // 1. 获取 sessionid
  const r = await ctx.http.get(
    `http://${cfg.host}/fh_api/tmp/FHNCAPIS?ajaxmethod=get_refresh_sessionid`,
    { headers: makeHeaders(cfg.host) }
  );
  const { sessionid } = await r.json();
  if (!sessionid) throw new Error('无法获取 sessionid');

  // 2. 构造加密payload
  const payload = JSON.stringify({
    ajaxmethod: 'login',
    loginUser: cfg.user,
    password: cfg.pass,
    sessionid,
  });

  // 3. AES-128-ECB 加密 (key = sessionid前16字节)
  const encHex = aesEcbEncryptHex(payload, sessionid.substring(0, 16));
  const body = randomPrefix() + encHex;

  // 4. POST 登录
  const random = Math.random().toString().slice(2);
  await ctx.http.post(
    `http://${cfg.host}/fh_api/tmp/FHNCAPIS?_${random}`,
    {
      headers: {
        ...makeHeaders(cfg.host),
        'Content-Type': 'application/json; charset=UTF-8',
        'Origin': `http://${cfg.host}`,
      },
      body,
    }
  );
}

// ==================== 网络模式映射 ====================

const NETWORK_MODE_MAP = {
  '0': '2G', '1': '3G', '2': '4G LTE',
  '3': '5G NSA', '4': '5G SA', '5': '5G',
};

// ==================== 数据获取 ====================

async function fetchAllData(ctx, cfg) {
  // 先尝试不登录，若失败则登录后重试
  let h, needLogin = false;
  try {
    h = await fhGet(ctx, cfg, 'FHAPIS', 'get_header_info');
  } catch (e) {
    if (e.message.includes('登录') || e.message.includes('HTML')) needLogin = true;
    else throw e;
  }

  if (needLogin) {
    await login(ctx, cfg);
    h = await fhGet(ctx, cfg, 'FHAPIS', 'get_header_info');
  }

  // 尝试获取NR信号详情(接口名不确定，失败静默)
  let nr = {};
  try { nr = await fhGet(ctx, cfg, 'FHAPIS', 'get_nr_cell_info'); } catch (_) {}

  const mode = String(h.NetworkMode ?? '');
  const rsrp  = pick(nr.RSRP,  h.RSRP);
  const rsrq  = pick(nr.RSRQ,  h.RSRQ);
  const sinr  = pick(nr.SINR,  h.SINR);
  const rssi  = pick(nr.RSSI,  h.RSSI);
  const pci   = nr.PCI   ?? h.PCI   ?? null;
  const band  = nr.BAND  ?? h.BAND  ?? null;
  const power = pick(nr.Power, h.Power);
  const cqi   = nr.CQI   ?? h.CQI   ?? null;
  const qci   = nr.QCI   ?? h.QCI   ?? null;
  const cellId = nr.CellId ?? nr.CELLID ?? nr['CELL ID'] ?? h.CellId ?? null;

  const wan = {
    connType: NETWORK_MODE_MAP[mode] || h.WanInterface || 'CPE',
    carrier: h.SPN || '',
    connected: h.connetStatus === 1 || h.cellularConnetStatus === 1,
    onlineDevs: Number(h.OnlineDevNum) || 0,
  };
  const traffic = {
    txBytes: Number(h.TotalBytesSent) || 0,
    rxBytes: Number(h.TotalBytesReceived) || 0,
  };
  const signal = {
    band: band != null ? String(band) : null,
    pci:  pci  != null ? String(pci)  : null,
    rsrp, rsrq, sinr, rssi, power,
    cqi: cqi != null ? String(cqi) : null,
    qci: qci != null ? String(qci) : null,
    cellId: cellId != null ? String(cellId) : null,
    signalLevel: Number(h.SignalLevel) || null,
  };
  return { wan, traffic, signal };
}

function pick(a, b) {
  const v = a ?? b;
  return v != null ? Number(v) : null;
}

// ==================== 速率计算 ====================

function calcSpeed(ctx, traffic) {
  const now = Date.now();
  const prev = ctx.storage.getJSON('prev_traffic');
  ctx.storage.setJSON('prev_traffic', { ...traffic, ts: now });
  if (!prev || !prev.ts) return { up: 0, down: 0 };
  const elapsed = (now - prev.ts) / 1000;
  if (elapsed <= 0 || elapsed > 300) return { up: 0, down: 0 };
  return {
    up:   Math.max(0, (traffic.txBytes - prev.txBytes) / elapsed),
    down: Math.max(0, (traffic.rxBytes - prev.rxBytes) / elapsed),
  };
}

function formatSpeed(bps) {
  if (bps < 1024)         return bps.toFixed(0) + ' B/s';
  if (bps < 1048576)      return (bps / 1024).toFixed(1) + ' KB/s';
  return (bps / 1048576).toFixed(2) + ' MB/s';
}

// ==================== 信号颜色 ====================

function rsrpColor(v) {
  if (v == null) return '#95A5A6';
  if (v >= -80)  return '#2ECC71';
  if (v >= -90)  return '#A8D835';
  if (v >= -100) return '#F7B731';
  if (v >= -110) return '#FC5C65';
  return '#B03A2E';
}
function sinrColor(v) {
  if (v == null) return '#95A5A6';
  if (v >= 20)  return '#2ECC71';
  if (v >= 13)  return '#A8D835';
  if (v >= 5)   return '#F7B731';
  if (v >= 0)   return '#FC5C65';
  return '#B03A2E';
}
function signalLabel(v) {
  if (v == null) return '未知';
  if (v >= -80)  return '极好';
  if (v >= -90)  return '良好';
  if (v >= -100) return '一般';
  if (v >= -110) return '差';
  return '极差';
}

// ==================== 颜色常量 ====================

const C = {
  bg1: '#0F1923', bg2: '#162736',
  title: '#5EC4E8', label: '#7A8FA0', value: '#E8ECF0',
  up: '#FF6B6B', down: '#51CF66',
  accent: '#5EC4E8', dim: '#4A5C6A',
};

// ==================== 通用组件 ====================

const dot = (rsrp, sz = 10) => ({
  type: 'stack', width: sz, height: sz,
  borderRadius: sz / 2, backgroundColor: rsrpColor(rsrp),
});

const infoRow = (icon, label, value, vc) => ({
  type: 'stack', direction: 'row', alignItems: 'center', gap: 5,
  children: [
    { type: 'image', src: `sf-symbol:${icon}`, color: C.accent, width: 12, height: 12 },
    { type: 'text', text: label, font: { size: 'caption2' }, textColor: C.label },
    { type: 'spacer' },
    { type: 'text', text: String(value), font: { size: 'caption2', weight: 'medium', family: 'Menlo' }, textColor: vc || C.value, maxLines: 1, minScale: 0.6 },
  ],
});

const sigRow = (label, value, vc) => ({
  type: 'stack', direction: 'row', alignItems: 'center',
  children: [
    { type: 'text', text: label, font: { size: 'caption2' }, textColor: C.label, width: 46 },
    { type: 'text', text: String(value), font: { size: 'caption2', weight: 'semibold', family: 'Menlo' }, textColor: vc || C.value },
  ],
});

const speedBlock = (dir, bps, color) => {
  const isUp = dir === 'up';
  return {
    type: 'stack', direction: 'column', alignItems: 'center', gap: 2,
    flex: 1, backgroundColor: C.bg2, borderRadius: 8, padding: [6, 4],
    children: [
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
        children: [
          { type: 'image', src: `sf-symbol:arrow.${isUp ? 'up' : 'down'}.circle.fill`, color, width: 12, height: 12 },
          { type: 'text', text: isUp ? '上行' : '下行', font: { size: 'caption2' }, textColor: C.label },
        ],
      },
      { type: 'text', text: formatSpeed(bps), font: { size: 'caption1', weight: 'bold', family: 'Menlo' }, textColor: color, maxLines: 1, minScale: 0.5 },
    ],
  };
};

const titleRow = (wan, signal, sz) => {
  const bandStr = signal.band ? `N${signal.band.replace(/^N/i, '')}` : wan.connType;
  return {
    type: 'stack', direction: 'row', alignItems: 'center', gap: 6,
    children: [
      { type: 'image', src: 'sf-symbol:antenna.radiowaves.left.and.right', color: C.title, width: sz, height: sz },
      { type: 'text', text: wan.carrier || wan.connType, font: { size: 'headline', weight: 'bold' }, textColor: C.title },
      { type: 'spacer' },
      dot(signal.rsrp, 10),
      { type: 'text', text: bandStr, font: { size: 'caption2', weight: 'medium' }, textColor: C.dim, backgroundColor: C.bg2, padding: [2, 6], borderRadius: 4 },
    ],
  };
};

// ==================== Widget 构建 ====================

function buildSmall(wan, speed, sig) {
  const bg = { type: 'linear', colors: [C.bg1, '#0D1520'], startPoint: {x:0,y:0}, endPoint: {x:0.5,y:1} };
  return {
    type: 'widget', backgroundGradient: bg, padding: 12, gap: 6,
    children: [
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 6,
        children: [
          { type: 'image', src: 'sf-symbol:antenna.radiowaves.left.and.right', color: C.title, width: 15, height: 15 },
          { type: 'text', text: wan.carrier || wan.connType, font: { size: 'caption1', weight: 'bold' }, textColor: C.title, maxLines: 1, minScale: 0.7 },
          { type: 'spacer' },
          dot(sig.rsrp, 10),
        ],
      },
      infoRow('dot.radiowaves.right', 'BAND', sig.band ? `N${sig.band.replace(/^N/i,'')}` : '--'),
      infoRow('cellularbars', 'RSRP', sig.rsrp != null ? `${sig.rsrp} dBm` : '--', rsrpColor(sig.rsrp)),
      infoRow('waveform',     'SINR', sig.sinr != null ? `${sig.sinr} dB`  : '--', sinrColor(sig.sinr)),
      { type: 'spacer' },
      { type: 'stack', direction: 'row', gap: 6, children: [speedBlock('up', speed.up, C.up), speedBlock('down', speed.down, C.down)] },
    ],
  };
}

function buildMedium(wan, speed, sig) {
  const bg = { type: 'linear', colors: [C.bg1, '#0D1520'], startPoint: {x:0,y:0}, endPoint: {x:0.5,y:1} };
  const f = (v, u) => v != null ? `${v} ${u}` : '--';
  return {
    type: 'widget', backgroundGradient: bg, padding: 14, gap: 6,
    children: [
      titleRow(wan, sig, 17),
      {
        type: 'stack', direction: 'row', gap: 12, flex: 1,
        children: [
          {
            type: 'stack', direction: 'column', gap: 4, flex: 1,
            children: [
              infoRow('dot.radiowaves.right', 'BAND', sig.band ? `N${sig.band.replace(/^N/i,'')}` : '--'),
              infoRow('number',    'PCI',  sig.pci  ?? '--'),
              infoRow('cellularbars', 'RSRP', f(sig.rsrp,'dBm'), rsrpColor(sig.rsrp)),
              infoRow('waveform',  'SINR', f(sig.sinr,'dB'),  sinrColor(sig.sinr)),
              infoRow('chart.bar', 'RSRQ', f(sig.rsrq,'dB')),
              infoRow('antenna.radiowaves.left.and.right', 'RSSI', f(sig.rssi,'dBm')),
            ],
          },
          {
            type: 'stack', direction: 'column', gap: 6, width: 104,
            children: [
              speedBlock('up', speed.up, C.up),
              speedBlock('down', speed.down, C.down),
              {
                type: 'stack', direction: 'row', alignItems: 'center', justifyContent: 'center', gap: 4,
                children: [
                  dot(sig.rsrp, 8),
                  { type: 'text', text: signalLabel(sig.rsrp), font: { size: 'caption2' }, textColor: rsrpColor(sig.rsrp) },
                ],
              },
            ],
          },
        ],
      },
    ],
  };
}

function buildLarge(wan, speed, sig) {
  const bg = { type: 'linear', colors: [C.bg1, '#0D1520'], startPoint: {x:0,y:0}, endPoint: {x:0.5,y:1} };
  const f = (v, u) => v != null ? `${v} ${u}` : '--';
  const bandStr = sig.band ? `N${sig.band.replace(/^N/i,'')}` : '--';
  return {
    type: 'widget', backgroundGradient: bg, padding: 16, gap: 8,
    children: [
      titleRow(wan, sig, 22),
      { type: 'stack', direction: 'row', gap: 12, children: [speedBlock('up', speed.up, C.up), speedBlock('down', speed.down, C.down)] },
      { type: 'stack', height: 1, backgroundColor: C.bg2 },
      {
        type: 'stack', direction: 'column', gap: 5,
        children: [
          {
            type: 'stack', direction: 'row', alignItems: 'center', gap: 6,
            children: [dot(sig.rsrp, 12), { type: 'text', text: `信号质量: ${signalLabel(sig.rsrp)}`, font: { size: 'caption1', weight: 'semibold' }, textColor: rsrpColor(sig.rsrp) }],
          },
          {
            type: 'stack', direction: 'row', gap: 8,
            children: [
              { type: 'stack', direction: 'column', gap: 5, flex: 1, children: [
                sigRow('BAND',  bandStr),
                sigRow('PCI',   sig.pci  ?? '--'),
                sigRow('RSRP',  f(sig.rsrp,'dBm'), rsrpColor(sig.rsrp)),
                sigRow('RSRQ',  f(sig.rsrq,'dB')),
              ]},
              { type: 'stack', direction: 'column', gap: 5, flex: 1, children: [
                sigRow('SINR',  f(sig.sinr,'dB'),  sinrColor(sig.sinr)),
                sigRow('RSSI',  f(sig.rssi,'dBm')),
                sigRow('Power', f(sig.power,'dBm')),
                sigRow('CQI',   sig.cqi ?? '--'),
              ]},
            ],
          },
          sig.cellId ? infoRow('number', 'Cell ID', sig.cellId) : null,
          sig.qci    ? sigRow('QCI', sig.qci)                  : null,
        ].filter(Boolean),
      },
      { type: 'stack', height: 1, backgroundColor: C.bg2 },
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 6,
        children: [
          wan.carrier ? { type: 'text', text: wan.carrier, font: { size: 'caption2' }, textColor: C.label } : null,
          { type: 'spacer' },
          wan.onlineDevs > 0 ? { type: 'text', text: `${wan.onlineDevs}台在线`, font: { size: 'caption2' }, textColor: C.dim } : null,
          { type: 'date', date: new Date().toISOString(), format: 'time', font: { size: 'caption2' }, textColor: C.dim },
        ].filter(Boolean),
      },
    ],
  };
}

function buildAccessory(speed, sig) {
  return {
    type: 'widget',
    children: [{
      type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
      children: [
        dot(sig.rsrp, 8),
        { type: 'text', text: `↑${formatSpeed(speed.up)} ↓${formatSpeed(speed.down)}`, font: { size: 'caption2', weight: 'medium', family: 'Menlo' } },
      ],
    }],
  };
}

function buildError(msg) {
  return {
    type: 'widget',
    backgroundGradient: { type: 'linear', colors: [C.bg1, '#0D1520'], startPoint: {x:0,y:0}, endPoint: {x:0.5,y:1} },
    padding: 16,
    children: [
      { type: 'stack', direction: 'row', alignItems: 'center', gap: 6, children: [
        { type: 'image', src: 'sf-symbol:exclamationmark.triangle.fill', color: '#FF6B6B', width: 18, height: 18 },
        { type: 'text', text: '烽火CPE', font: { size: 'headline', weight: 'bold' }, textColor: C.title },
      ]},
      { type: 'spacer' },
      { type: 'text', text: msg, font: { size: 'caption1' }, textColor: '#FF6B6B' },
      { type: 'text', text: 'CPE_HOST / CPE_USER / CPE_PASS', font: { size: 'caption2' }, textColor: C.dim },
    ],
  };
}

// ==================== 主入口 ====================

export default async function (ctx) {
  const cfg = getConfig(ctx);
  try {
    const { wan, traffic, signal } = await fetchAllData(ctx, cfg);
    const speed = calcSpeed(ctx, traffic);
    const f = ctx.widgetFamily;
    if (f === 'accessoryRectangular' || f === 'accessoryInline' || f === 'accessoryCircular')
      return buildAccessory(speed, signal);
    if (f === 'systemLarge' || f === 'systemExtraLarge')
      return buildLarge(wan, speed, signal);
    if (f === 'systemMedium')
      return buildMedium(wan, speed, signal);
    return buildSmall(wan, speed, signal);
  } catch (e) {
    return buildError(e.message || '连接失败');
  }
}
