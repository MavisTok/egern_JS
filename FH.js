/**
 * 烽火CPE状态小组件 - Egern Widget
 * 显示5G NR信号详情(BAND/RSRP/RSRQ/SINR/PCI等)和实时上下行速率
 *
 * 环境变量:
 *   CPE_HOST: CPE管理地址，默认 192.168.8.1
 */

// ==================== 配置 ====================

function getConfig(ctx) {
  return {
    host: ctx.env.CPE_HOST || '192.168.8.1',
  };
}

// ==================== 网络模式映射 ====================

const NETWORK_MODE_MAP = {
  '0': '2G', '1': '3G', '2': '4G LTE',
  '3': '5G NSA', '4': '5G SA', '5': '5G',
};

// ==================== 信号强度颜色(基于RSRP) ====================

/**
 * RSRP 分级:
 *   ≥ -80        极好  绿
 *   -80 ~ -90    良好  黄绿
 *   -90 ~ -100   一般  橙
 *   -100 ~ -110  差    红橙
 *   < -110       极差  灰红
 */
function rsrpColor(rsrp) {
  if (rsrp == null || isNaN(rsrp)) return '#95A5A6';
  if (rsrp >= -80)  return '#2ECC71';
  if (rsrp >= -90)  return '#A8D835';
  if (rsrp >= -100) return '#F7B731';
  if (rsrp >= -110) return '#FC5C65';
  return '#B03A2E';
}

function sinrColor(sinr) {
  if (sinr == null || isNaN(sinr)) return '#95A5A6';
  if (sinr >= 20)  return '#2ECC71';
  if (sinr >= 13)  return '#A8D835';
  if (sinr >= 5)   return '#F7B731';
  if (sinr >= 0)   return '#FC5C65';
  return '#B03A2E';
}

function signalLabel(rsrp) {
  if (rsrp == null || isNaN(rsrp)) return '未知';
  if (rsrp >= -80)  return '极好';
  if (rsrp >= -90)  return '良好';
  if (rsrp >= -100) return '一般';
  if (rsrp >= -110) return '差';
  return '极差';
}

// ==================== CPE 接口 ====================

async function fhGet(ctx, cfg, ajaxmethod) {
  const resp = await ctx.http.get(
    `http://${cfg.host}/fh_api/tmp/FHAPIS?ajaxmethod=${ajaxmethod}`,
    { headers: { 'X-Requested-With': 'XMLHttpRequest' } }
  );
  return await resp.json();
}

async function fetchAllData(ctx, cfg) {
  // 并发拉取头部信息和NR信号信息
  const [header, nrRaw] = await Promise.allSettled([
    fhGet(ctx, cfg, 'get_header_info'),
    fhGet(ctx, cfg, 'get_nr_cell_info'),
  ]);

  const h = header.status === 'fulfilled' ? header.value : {};
  const nr = nrRaw.status === 'fulfilled' ? nrRaw.value : {};

  const mode = String(h.NetworkMode ?? '');

  // NR信号字段，优先使用 nr 接口，回退到 header
  const rsrp  = nr.RSRP  != null ? Number(nr.RSRP)  : (h.RSRP  != null ? Number(h.RSRP)  : null);
  const rsrq  = nr.RSRQ  != null ? Number(nr.RSRQ)  : (h.RSRQ  != null ? Number(h.RSRQ)  : null);
  const sinr  = nr.SINR  != null ? Number(nr.SINR)  : (h.SINR  != null ? Number(h.SINR)  : null);
  const rssi  = nr.RSSI  != null ? Number(nr.RSSI)  : (h.RSSI  != null ? Number(h.RSSI)  : null);
  const pci   = nr.PCI   != null ? String(nr.PCI)   : (h.PCI   != null ? String(h.PCI)   : null);
  const band  = nr.BAND  != null ? String(nr.BAND)  : (h.BAND  != null ? String(h.BAND)  : null);
  const power = nr.Power != null ? Number(nr.Power) : (h.Power != null ? Number(h.Power) : null);
  const cqi   = nr.CQI   != null ? String(nr.CQI)   : (h.CQI   != null ? String(h.CQI)   : null);
  const qci   = nr.QCI   != null ? String(nr.QCI)   : (h.QCI   != null ? String(h.QCI)   : null);
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
    band, pci, rsrp, rsrq, sinr, rssi, power, cqi, qci,
    cellId: cellId != null ? String(cellId) : null,
    signalLevel: Number(h.SignalLevel) || null,
  };

  return { wan, traffic, signal };
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
  if (bps < 1024)           return bps.toFixed(0) + ' B/s';
  if (bps < 1024 * 1024)   return (bps / 1024).toFixed(1) + ' KB/s';
  return (bps / 1024 / 1024).toFixed(2) + ' MB/s';
}

// ==================== 颜色 ====================

const colors = {
  bg1: '#0F1923', bg2: '#162736',
  title: '#5EC4E8', label: '#7A8FA0', value: '#E8ECF0',
  up: '#FF6B6B', down: '#51CF66',
  accent: '#5EC4E8', dim: '#4A5C6A',
};

// ==================== 通用组件 ====================

/** 信号强度彩色圆点 */
function signalDot(rsrp, size = 10) {
  return {
    type: 'stack',
    width: size, height: size,
    borderRadius: size / 2,
    backgroundColor: rsrpColor(rsrp),
  };
}

/** 标准信息行: [图标] 标签 ......... 值 */
function infoRow(icon, label, value, valueColor) {
  return {
    type: 'stack', direction: 'row', alignItems: 'center', gap: 5,
    children: [
      { type: 'image', src: `sf-symbol:${icon}`, color: colors.accent, width: 12, height: 12 },
      { type: 'text', text: label, font: { size: 'caption2' }, textColor: colors.label },
      { type: 'spacer' },
      { type: 'text', text: String(value), font: { size: 'caption2', weight: 'medium', family: 'Menlo' }, textColor: valueColor || colors.value, maxLines: 1, minScale: 0.6 },
    ],
  };
}

/** 速率块 */
function speedBlock(direction, bps, color) {
  const isUp = direction === 'up';
  return {
    type: 'stack', direction: 'column', alignItems: 'center', gap: 2,
    flex: 1, backgroundColor: colors.bg2, borderRadius: 8, padding: [6, 4],
    children: [
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
        children: [
          { type: 'image', src: `sf-symbol:arrow.${isUp ? 'up' : 'down'}.circle.fill`, color, width: 12, height: 12 },
          { type: 'text', text: isUp ? '上行' : '下行', font: { size: 'caption2' }, textColor: colors.label },
        ],
      },
      { type: 'text', text: formatSpeed(bps), font: { size: 'caption1', weight: 'bold', family: 'Menlo' }, textColor: color, maxLines: 1, minScale: 0.5 },
    ],
  };
}

/** NR信号值行，值带颜色(无图标，双列对齐用) */
function sigRow(label, value, valueColor) {
  return {
    type: 'stack', direction: 'row', alignItems: 'center',
    children: [
      { type: 'text', text: label, font: { size: 'caption2' }, textColor: colors.label, width: 44 },
      { type: 'text', text: String(value), font: { size: 'caption2', weight: 'semibold', family: 'Menlo' }, textColor: valueColor || colors.value },
    ],
  };
}

// ==================== 标题行(含信号圆点) ====================

function titleRow(wan, signal, iconSize) {
  const dot = signalDot(signal.rsrp, 10);
  const bandText = signal.band ? `N${signal.band.replace(/^N/i, '')}` : wan.connType;
  const carrierText = wan.carrier || wan.connType;
  return {
    type: 'stack', direction: 'row', alignItems: 'center', gap: 6,
    children: [
      { type: 'image', src: 'sf-symbol:antenna.radiowaves.left.and.right', color: colors.title, width: iconSize, height: iconSize },
      { type: 'text', text: carrierText, font: { size: 'headline', weight: 'bold' }, textColor: colors.title },
      { type: 'spacer' },
      dot,
      { type: 'text', text: bandText, font: { size: 'caption2', weight: 'medium' }, textColor: colors.dim, backgroundColor: colors.bg2, padding: [2, 6], borderRadius: 4 },
    ],
  };
}

// ==================== Widget 构建 ====================

function buildSmallWidget(wan, speed, signal) {
  const rsrpStr = signal.rsrp != null ? `${signal.rsrp} dBm` : '--';
  const sinrStr = signal.sinr != null ? `${signal.sinr} dB`  : '--';
  return {
    type: 'widget',
    backgroundGradient: { type: 'linear', colors: [colors.bg1, '#0D1520'], startPoint: { x: 0, y: 0 }, endPoint: { x: 0.5, y: 1 } },
    padding: 12, gap: 6,
    children: [
      // 标题 + 信号圆点
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 6,
        children: [
          { type: 'image', src: 'sf-symbol:antenna.radiowaves.left.and.right', color: colors.title, width: 15, height: 15 },
          { type: 'text', text: wan.carrier || wan.connType, font: { size: 'caption1', weight: 'bold' }, textColor: colors.title, maxLines: 1, minScale: 0.7 },
          { type: 'spacer' },
          signalDot(signal.rsrp, 10),
        ],
      },
      infoRow('dot.radiowaves.right', 'BAND', signal.band ? `N${signal.band.replace(/^N/i, '')}` : '--'),
      infoRow('cellularbars', 'RSRP', rsrpStr, rsrpColor(signal.rsrp)),
      infoRow('waveform', 'SINR', sinrStr, sinrColor(signal.sinr)),
      { type: 'spacer' },
      {
        type: 'stack', direction: 'row', gap: 6,
        children: [speedBlock('up', speed.up, colors.up), speedBlock('down', speed.down, colors.down)],
      },
    ],
  };
}

function buildMediumWidget(wan, speed, signal) {
  const rsrpStr  = signal.rsrp  != null ? `${signal.rsrp} dBm`  : '--';
  const rsrqStr  = signal.rsrq  != null ? `${signal.rsrq} dB`   : '--';
  const sinrStr  = signal.sinr  != null ? `${signal.sinr} dB`   : '--';
  const rssiStr  = signal.rssi  != null ? `${signal.rssi} dBm`  : '--';
  const bandStr  = signal.band  ? `N${signal.band.replace(/^N/i, '')}` : '--';
  const pciStr   = signal.pci   ?? '--';

  return {
    type: 'widget',
    backgroundGradient: { type: 'linear', colors: [colors.bg1, '#0D1520'], startPoint: { x: 0, y: 0 }, endPoint: { x: 0.5, y: 1 } },
    padding: 14, gap: 6,
    children: [
      titleRow(wan, signal, 17),
      {
        type: 'stack', direction: 'row', gap: 12, flex: 1,
        children: [
          // 左: 信号详情
          {
            type: 'stack', direction: 'column', gap: 4, flex: 1,
            children: [
              infoRow('dot.radiowaves.right',  'BAND', bandStr),
              infoRow('number',                'PCI',  pciStr),
              infoRow('cellularbars',          'RSRP', rsrpStr,  rsrpColor(signal.rsrp)),
              infoRow('waveform',              'SINR', sinrStr,  sinrColor(signal.sinr)),
              infoRow('chart.bar',             'RSRQ', rsrqStr),
              infoRow('antenna.radiowaves.left.and.right', 'RSSI', rssiStr),
            ],
          },
          // 右: 速率
          {
            type: 'stack', direction: 'column', gap: 6, width: 104,
            children: [
              speedBlock('up', speed.up, colors.up),
              speedBlock('down', speed.down, colors.down),
              // 信号质量标签
              {
                type: 'stack', direction: 'row', alignItems: 'center', justifyContent: 'center', gap: 4,
                children: [
                  signalDot(signal.rsrp, 8),
                  { type: 'text', text: signalLabel(signal.rsrp), font: { size: 'caption2' }, textColor: rsrpColor(signal.rsrp) },
                ],
              },
            ],
          },
        ],
      },
    ],
  };
}

function buildLargeWidget(wan, speed, signal) {
  const fmt = (v, unit) => v != null ? `${v} ${unit}` : '--';
  const bandStr = signal.band ? `N${signal.band.replace(/^N/i, '')}` : '--';

  return {
    type: 'widget',
    backgroundGradient: { type: 'linear', colors: [colors.bg1, '#0D1520'], startPoint: { x: 0, y: 0 }, endPoint: { x: 0.5, y: 1 } },
    padding: 16, gap: 8,
    children: [
      titleRow(wan, signal, 22),

      // 速率区
      { type: 'stack', direction: 'row', gap: 12, children: [speedBlock('up', speed.up, colors.up), speedBlock('down', speed.down, colors.down)] },

      // 分隔线
      { type: 'stack', height: 1, backgroundColor: colors.bg2 },

      // 信号详情 — 双列网格
      {
        type: 'stack', direction: 'column', gap: 5,
        children: [
          // 信号质量头
          {
            type: 'stack', direction: 'row', alignItems: 'center', gap: 6,
            children: [
              signalDot(signal.rsrp, 12),
              { type: 'text', text: `信号质量: ${signalLabel(signal.rsrp)}`, font: { size: 'caption1', weight: 'semibold' }, textColor: rsrpColor(signal.rsrp) },
            ],
          },
          // 双列: 左右各4行
          {
            type: 'stack', direction: 'row', gap: 8,
            children: [
              {
                type: 'stack', direction: 'column', gap: 5, flex: 1,
                children: [
                  sigRow('BAND',  bandStr),
                  sigRow('PCI',   signal.pci  ?? '--'),
                  sigRow('RSRP',  fmt(signal.rsrp, 'dBm'), rsrpColor(signal.rsrp)),
                  sigRow('RSRQ',  fmt(signal.rsrq, 'dB')),
                ],
              },
              {
                type: 'stack', direction: 'column', gap: 5, flex: 1,
                children: [
                  sigRow('SINR',    fmt(signal.sinr,  'dB'),  sinrColor(signal.sinr)),
                  sigRow('RSSI',    fmt(signal.rssi,  'dBm')),
                  sigRow('Power',   fmt(signal.power, 'dBm')),
                  sigRow('CQI',     signal.cqi ?? '--'),
                ],
              },
            ],
          },
          // CELL ID 独占一行(值较长)
          signal.cellId ? infoRow('number', 'Cell ID', signal.cellId) : null,
          // QCI
          signal.qci ? sigRow('QCI', signal.qci) : null,
        ].filter(Boolean),
      },

      // 分隔线
      { type: 'stack', height: 1, backgroundColor: colors.bg2 },

      // 底部: 运营商 + 在线设备数 + 时间
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 6,
        children: [
          wan.carrier ? { type: 'text', text: wan.carrier, font: { size: 'caption2' }, textColor: colors.label } : null,
          { type: 'spacer' },
          wan.onlineDevs > 0
            ? { type: 'text', text: `${wan.onlineDevs}台在线`, font: { size: 'caption2' }, textColor: colors.dim }
            : null,
          { type: 'date', date: new Date().toISOString(), format: 'time', font: { size: 'caption2' }, textColor: colors.dim },
        ].filter(Boolean),
      },
    ],
  };
}

function buildAccessoryWidget(speed, signal) {
  const dot = signal.rsrp != null
    ? { type: 'stack', width: 8, height: 8, borderRadius: 4, backgroundColor: rsrpColor(signal.rsrp) }
    : null;
  return {
    type: 'widget',
    children: [
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
        children: [
          dot,
          { type: 'text', text: `↑${formatSpeed(speed.up)} ↓${formatSpeed(speed.down)}`, font: { size: 'caption2', weight: 'medium', family: 'Menlo' } },
        ].filter(Boolean),
      },
    ],
  };
}

function buildErrorWidget(msg) {
  return {
    type: 'widget',
    backgroundGradient: { type: 'linear', colors: [colors.bg1, '#0D1520'], startPoint: { x: 0, y: 0 }, endPoint: { x: 0.5, y: 1 } },
    padding: 16,
    children: [
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 6,
        children: [
          { type: 'image', src: 'sf-symbol:exclamationmark.triangle.fill', color: '#FF6B6B', width: 18, height: 18 },
          { type: 'text', text: '烽火CPE', font: { size: 'headline', weight: 'bold' }, textColor: colors.title },
        ],
      },
      { type: 'spacer' },
      { type: 'text', text: msg, font: { size: 'caption1' }, textColor: '#FF6B6B' },
      { type: 'text', text: '请检查CPE地址配置', font: { size: 'caption2' }, textColor: colors.dim },
    ],
  };
}

// ==================== 主入口 ====================

export default async function (ctx) {
  const cfg = getConfig(ctx);

  try {
    const { wan, traffic, signal } = await fetchAllData(ctx, cfg);
    const speed = calcSpeed(ctx, traffic);
    const family = ctx.widgetFamily;

    if (family === 'accessoryRectangular' || family === 'accessoryInline' || family === 'accessoryCircular') {
      return buildAccessoryWidget(speed, signal);
    }
    if (family === 'systemLarge' || family === 'systemExtraLarge') {
      return buildLargeWidget(wan, speed, signal);
    }
    if (family === 'systemMedium') {
      return buildMediumWidget(wan, speed, signal);
    }
    return buildSmallWidget(wan, speed, signal);
  } catch (e) {
    return buildErrorWidget(e.message || '连接失败');
  }
}
