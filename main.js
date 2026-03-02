#!/usr/bin/env node

/**
 * Port Monitor - Hecaton Plugin
 *
 * Monitors active network ports using netstat and provides
 * process management through context menus.
 *
 * Keyboard:
 *   Up/Down   - Select row
 *   PgUp/PgDn - Page scroll
 *   Home/End  - Jump to first/last
 *   r         - Refresh
 *   /         - Search (input dialog)
 *   f         - Cycle state filter
 *   p         - Cycle protocol filter
 *   k         - Kill selected process
 *   a         - Toggle auto refresh
 *   c         - Copy selected line
 *   ESC       - Close (handled by host)
 *
 * Right-click: Zone-based context menu
 */

// ============================================================
// 1. ANSI Helpers
// ============================================================
const ESC = '\x1b';
const CSI = ESC + '[';

const ansi = {
  clear: CSI + '2J' + CSI + 'H',
  hideCursor: CSI + '?25l',
  showCursor: CSI + '?25h',
  reset: CSI + '0m',
  bold: CSI + '1m',
  dim: CSI + '2m',
  italic: CSI + '3m',
  underline: CSI + '4m',
  inverse: CSI + '7m',
  moveTo: (row, col) => `${CSI}${row};${col}H`,
  eraseLine: CSI + '2K',
  fg: {
    black: CSI + '30m', red: CSI + '31m', green: CSI + '32m',
    yellow: CSI + '33m', blue: CSI + '34m', magenta: CSI + '35m',
    cyan: CSI + '36m', white: CSI + '37m', default: CSI + '39m',
  },
  bg: {
    black: CSI + '40m', red: CSI + '41m', green: CSI + '42m',
    yellow: CSI + '43m', blue: CSI + '44m', magenta: CSI + '45m',
    cyan: CSI + '46m', white: CSI + '47m', default: CSI + '49m',
  },
};

// ============================================================
// 2. State
// ============================================================
let termCols = parseInt(process.env.HECA_COLS || '120', 10);
let termRows = parseInt(process.env.HECA_ROWS || '30', 10);
let minimized = false;
let rpcId = 1;
const pendingRpc = new Map();

// Port data
let portEntries = [];      // raw parsed entries
let filteredEntries = [];  // after filter/sort
let selectedIndex = 0;     // index in filteredEntries
let scrollOffset = 0;      // first visible row index

// Filter/sort state
const STATES = ['ALL', 'LISTENING', 'ESTABLISHED', 'TIME_WAIT', 'CLOSE_WAIT', 'FIN_WAIT_2', 'SYN_SENT'];
const PROTOS = ['ALL', 'TCP', 'UDP'];
let stateFilterIdx = 0;
let protoFilterIdx = 0;
let searchQuery = '';

// Sort state
let sortColumn = 'proto';
let sortAsc = true;

// Auto refresh
let autoRefresh = true;
let autoRefreshTimer = null;
const AUTO_REFRESH_INTERVAL = 3000;

// Process name cache
let processCache = new Map();  // pid -> name
let processCacheTime = 0;
const PROCESS_CACHE_TTL = 10000;

// Data collection state
let collecting = false;
let lastUpdated = '';
let loadingTimer = null;

// Cell size for sixel scrollbar
let cellW = 8;
let cellH = 16;

// Scrollbar state
let scrollbarOverlay = null;  // { sixelStr, screenRow, screenCol, viewportRows, maxScroll }
let dragging = null;          // 'scrollbar' | null
let scrollbarDragInfo = null; // { trackTop, trackH, maxScroll }

// ============================================================
// 3. RPC Helpers
// ============================================================
function sendRpc(method, params = {}) {
  const id = rpcId++;
  const msg = JSON.stringify({ jsonrpc: '2.0', method, params, id });
  process.stderr.write('__HECA_RPC__' + msg + '\n');
  return new Promise((resolve) => {
    pendingRpc.set(id, resolve);
    setTimeout(() => {
      if (pendingRpc.has(id)) {
        pendingRpc.delete(id);
        resolve(null);
      }
    }, 5000);
  });
}

function handleRpcResponse(json) {
  if (json.id != null && pendingRpc.has(json.id)) {
    const resolve = pendingRpc.get(json.id);
    pendingRpc.delete(json.id);
    resolve(json.result || null);
  }
}

// ============================================================
// 4. Data Collection
// ============================================================
const { exec, execSync } = require('child_process');

function execAsync(cmd, opts) {
  return new Promise((resolve) => {
    exec(cmd, opts, (err, stdout) => {
      resolve(err ? '' : stdout);
    });
  });
}

async function refreshProcessCache() {
  const now = Date.now();
  if (now - processCacheTime < PROCESS_CACHE_TTL && processCache.size > 0) return;
  try {
    const out = await execAsync('tasklist /FO CSV /NH', {
      encoding: 'utf-8',
      timeout: 5000,
      windowsHide: true,
    });
    const newCache = new Map();
    for (const line of out.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const match = trimmed.match(/^"([^"]+)","(\d+)"/);
      if (match) {
        newCache.set(match[2], match[1]);
      }
    }
    processCache = newCache;
    processCacheTime = now;
  } catch {
    // keep old cache on error
  }
}

async function collectPortData() {
  if (collecting) return;
  collecting = true;
  // Animate spinner while loading (only when data is empty)
  if (filteredEntries.length === 0) {
    loadingTimer = setInterval(() => rerender(), 120);
    rerender();
  }
  try {
    const [netstatOut] = await Promise.all([
      execAsync('netstat -ano', { encoding: 'utf-8', timeout: 10000, windowsHide: true }),
      refreshProcessCache(),
    ]);
    const entries = [];
    for (const line of netstatOut.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length < 4) continue;
      const proto = parts[0].toUpperCase();
      if (proto !== 'TCP' && proto !== 'UDP') continue;

      let localAddr, remoteAddr, state, pid;
      if (proto === 'UDP') {
        localAddr = parts[1];
        remoteAddr = parts[2] || '*:*';
        state = '';
        pid = parts[3] || parts[2];
        if (/^\d+$/.test(remoteAddr)) {
          pid = remoteAddr;
          remoteAddr = '*:*';
        }
      } else {
        localAddr = parts[1];
        remoteAddr = parts[2];
        state = parts[3] || '';
        pid = parts[4] || '';
      }

      const processName = processCache.get(pid) || '';
      entries.push({ proto, localAddr, remoteAddr, state, pid, processName });
    }
    portEntries = entries;
    lastUpdated = new Date().toLocaleTimeString('en-US', { hour12: false });
    applyFilterAndSort();
  } catch {
    // keep old data on error
  }
  collecting = false;
  if (loadingTimer) { clearInterval(loadingTimer); loadingTimer = null; }
  rerender();
}

// ============================================================
// 5. Filter & Sort
// ============================================================
function applyFilterAndSort() {
  let entries = portEntries.slice();

  // State filter
  const stateFilter = STATES[stateFilterIdx];
  if (stateFilter !== 'ALL') {
    entries = entries.filter(e => e.state === stateFilter);
  }

  // Protocol filter
  const protoFilter = PROTOS[protoFilterIdx];
  if (protoFilter !== 'ALL') {
    entries = entries.filter(e => e.proto === protoFilter);
  }

  // Search
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    entries = entries.filter(e =>
      e.proto.toLowerCase().includes(q) ||
      e.localAddr.toLowerCase().includes(q) ||
      e.remoteAddr.toLowerCase().includes(q) ||
      e.state.toLowerCase().includes(q) ||
      e.pid.includes(q) ||
      e.processName.toLowerCase().includes(q)
    );
  }

  // Sort
  entries.sort((a, b) => {
    let va, vb;
    switch (sortColumn) {
      case 'proto':     va = a.proto;       vb = b.proto; break;
      case 'local':     va = a.localAddr;   vb = b.localAddr; break;
      case 'remote':    va = a.remoteAddr;  vb = b.remoteAddr; break;
      case 'state':     va = a.state;       vb = b.state; break;
      case 'pid':       va = parseInt(a.pid) || 0; vb = parseInt(b.pid) || 0;
                        return sortAsc ? va - vb : vb - va;
      case 'process':   va = a.processName; vb = b.processName; break;
      default:          va = a.proto;       vb = b.proto; break;
    }
    if (typeof va === 'string') {
      const cmp = va.localeCompare(vb);
      return sortAsc ? cmp : -cmp;
    }
    return 0;
  });

  filteredEntries = entries;

  // Clamp selection
  if (selectedIndex >= filteredEntries.length) {
    selectedIndex = Math.max(0, filteredEntries.length - 1);
  }
  clampScroll();
}

function getMaxScroll() {
  return Math.max(0, filteredEntries.length - getDataRowCount());
}

function clampScroll() {
  const dataRows = getDataRowCount();
  const maxScroll = getMaxScroll();

  // Clamp selectedIndex first
  if (filteredEntries.length === 0) {
    selectedIndex = 0;
    scrollOffset = 0;
    return;
  }
  if (selectedIndex < 0) selectedIndex = 0;
  if (selectedIndex >= filteredEntries.length) selectedIndex = filteredEntries.length - 1;

  // Clamp scrollOffset
  if (scrollOffset > maxScroll) scrollOffset = maxScroll;
  if (scrollOffset < 0) scrollOffset = 0;

  // Ensure selected is visible
  if (selectedIndex < scrollOffset) scrollOffset = selectedIndex;
  if (selectedIndex >= scrollOffset + dataRows) scrollOffset = selectedIndex - dataRows + 1;
}

function getDataRowCount() {
  // Rows: 1=colheader, 2=sep
  return Math.max(1, termRows - 2);
}

// ============================================================
// 6. Rendering
// ============================================================
function rerender() {
  if (minimized) {
    renderMinimized();
  } else {
    render();
  }
}

function renderMinimized() {
  let tcpCount = 0, udpCount = 0, listenCount = 0, estCount = 0;
  for (const e of portEntries) {
    if (e.proto === 'TCP') tcpCount++;
    else if (e.proto === 'UDP') udpCount++;
    if (e.state === 'LISTENING') listenCount++;
    else if (e.state === 'ESTABLISHED') estCount++;
  }
  const text = `TCP:${tcpCount} UDP:${udpCount} | LISTEN:${listenCount} EST:${estCount}`;
  sendRpc('set_minimized_label', { label: text });
}

function getStateColor(state) {
  switch (state) {
    case 'LISTENING':   return ansi.fg.green;
    case 'ESTABLISHED': return ansi.fg.cyan;
    case 'TIME_WAIT':   return ansi.fg.yellow;
    case 'CLOSE_WAIT':  return ansi.fg.red;
    case 'FIN_WAIT_1':
    case 'FIN_WAIT_2':  return ansi.fg.magenta;
    case 'SYN_SENT':
    case 'SYN_RECEIVED':return ansi.fg.yellow;
    case 'LAST_ACK':    return ansi.fg.red;
    default:            return ansi.fg.default;
  }
}

function pad(text, w) {
  const plain = text.replace(/\x1b\[[0-9;]*m/g, '');
  return text + ' '.repeat(Math.max(0, w - plain.length));
}

function truncate(str, maxLen) {
  if (str.length <= maxLen) return str;
  return str.substring(0, maxLen - 1) + '\u2026';
}

// ---- Sixel Scrollbar ----
const SCROLLBAR_PALETTE = [[100, 110, 130]];
const SCROLLBAR_ACTIVE_PALETTE = [[210, 225, 245]];

function renderScrollbarPixels(cW, cH, viewportRows, offset, maxScroll) {
  if (maxScroll <= 0) return null;
  const w = cW;
  const trackH = viewportRows * cH;
  if (w <= 0 || trackH <= 0) return null;
  const totalItems = viewportRows + maxScroll;
  const handleH = Math.max(cH, Math.floor(trackH * viewportRows / totalItems));
  const handleY = Math.floor((trackH - handleH) * offset / maxScroll);
  const buf = new Uint8Array(w * trackH);
  const padX = 2;
  const roundY = 1;
  for (let y = handleY; y < handleY + handleH && y < trackH; y++) {
    const dy = y - handleY;
    const dyEnd = handleY + handleH - 1 - y;
    for (let x = padX; x < w - padX; x++) {
      if (dy < roundY && (x === padX || x === w - padX - 1)) continue;
      if (dyEnd < roundY && (x === padX || x === w - padX - 1)) continue;
      buf[y * w + x] = 1;
    }
  }
  return buf;
}

function encodeSixel(buf, w, h, palette) {
  let out = '\x1bP0;1;0q';
  out += '"1;1;' + w + ';' + h;
  for (let i = 0; i < palette.length; i++) {
    const [r, g, b] = palette[i];
    out += '#' + (i + 1) + ';2;' + Math.round(r * 100 / 255) +
           ';' + Math.round(g * 100 / 255) + ';' + Math.round(b * 100 / 255);
  }
  for (let bandY = 0; bandY < h; bandY += 6) {
    const bandH = Math.min(6, h - bandY);
    let bandHasData = false;
    for (let ci = 1; ci <= palette.length; ci++) {
      let row = '';
      let runChar = '';
      let runLen = 0;
      for (let x = 0; x < w; x++) {
        let bits = 0;
        for (let dy = 0; dy < bandH; dy++) {
          if (buf[(bandY + dy) * w + x] === ci) bits |= (1 << dy);
        }
        const ch = String.fromCharCode(63 + bits);
        if (ch === runChar) { runLen++; }
        else {
          if (runLen > 0) {
            if (runLen >= 4) row += '!' + runLen + runChar;
            else row += runChar.repeat(runLen);
          }
          runChar = ch; runLen = 1;
        }
      }
      if (runLen > 0) {
        if (runLen >= 4) row += '!' + runLen + runChar;
        else row += runChar.repeat(runLen);
      }
      if (row.replace(/[!0-9]/g, '').replace(/\?/g, '') === '') continue;
      bandHasData = true;
      out += '#' + ci + row + '$';
    }
    if (bandHasData && out.endsWith('$')) out = out.slice(0, -1);
    out += '-';
  }
  if (out.endsWith('-')) out = out.slice(0, -1);
  out += '\x1b\\';
  return out;
}

function render() {
  const out = [];
  const w = termCols;

  // Column widths (adaptive)
  const COL = computeColumns(w);

  // Row 1: Column headers
  const sortIndicator = (col) => {
    if (sortColumn === col) return sortAsc ? ' \u25B2' : ' \u25BC';
    return '';
  };
  let headerLine = ' ';
  headerLine += pad(ansi.bold + ansi.fg.white + 'PROTO' + sortIndicator('proto') + ansi.reset, COL.proto);
  headerLine += pad(ansi.bold + ansi.fg.white + 'LOCAL ADDRESS' + sortIndicator('local') + ansi.reset, COL.local);
  headerLine += pad(ansi.bold + ansi.fg.white + 'REMOTE ADDRESS' + sortIndicator('remote') + ansi.reset, COL.remote);
  headerLine += pad(ansi.bold + ansi.fg.white + 'STATE' + sortIndicator('state') + ansi.reset, COL.state);
  headerLine += pad(ansi.bold + ansi.fg.white + 'PID' + sortIndicator('pid') + ansi.reset, COL.pid);
  headerLine += ansi.bold + ansi.fg.white + 'PROCESS' + sortIndicator('process') + ansi.reset;
  out.push(pad(headerLine, w));

  // Row 2: Separator
  out.push(pad(ansi.dim + ' ' + '\u2500'.repeat(Math.max(0, w - 2)) + ansi.reset, w));

  // Row 3~N: Data rows
  const dataRows = getDataRowCount();

  // Loading indicator when no data yet
  if (filteredEntries.length === 0 && collecting) {
    const spinChars = ['\u280B', '\u2819', '\u2838', '\u2834', '\u2826', '\u2807'];
    const spinIdx = Math.floor(Date.now() / 120) % spinChars.length;
    const loadMsg = ansi.fg.yellow + ' ' + spinChars[spinIdx] + ' Loading...' + ansi.reset;
    out.push(pad(loadMsg, w));
    for (let i = 1; i < dataRows; i++) out.push(' '.repeat(w));

    process.stdout.write(ansi.clear + ansi.hideCursor);
    for (let i = 0; i < out.length; i++) {
      process.stdout.write(ansi.moveTo(i + 1, 1) + out[i]);
    }
    scrollbarOverlay = null;
    return;
  }

  for (let i = 0; i < dataRows; i++) {
    const idx = scrollOffset + i;
    if (idx >= filteredEntries.length) {
      out.push(' '.repeat(w));
      continue;
    }
    const entry = filteredEntries[idx];
    const isSelected = idx === selectedIndex;
    const stateColor = getStateColor(entry.state);

    const processMaxLen = Math.max(1, w - COL.proto - COL.local - COL.remote - COL.state - COL.pid - 2);
    let line;
    if (isSelected) {
      // No intermediate resets — inverse stays active across the entire line
      line = ansi.inverse + ' ' +
        pad(ansi.fg.white + truncate(entry.proto, COL.proto - 1), COL.proto) +
        pad(ansi.fg.cyan + truncate(entry.localAddr, COL.local - 1), COL.local) +
        pad(ansi.fg.white + truncate(entry.remoteAddr, COL.remote - 1), COL.remote) +
        pad(stateColor + truncate(entry.state, COL.state - 1), COL.state) +
        pad(ansi.fg.yellow + truncate(entry.pid, COL.pid - 1), COL.pid) +
        ansi.fg.magenta + truncate(entry.processName, processMaxLen) +
        ansi.reset;
    } else {
      line = ' ' +
        pad(ansi.fg.white + truncate(entry.proto, COL.proto - 1) + ansi.reset, COL.proto) +
        pad(ansi.fg.cyan + truncate(entry.localAddr, COL.local - 1) + ansi.reset, COL.local) +
        pad(ansi.dim + truncate(entry.remoteAddr, COL.remote - 1) + ansi.reset, COL.remote) +
        pad(stateColor + truncate(entry.state, COL.state - 1) + ansi.reset, COL.state) +
        pad(ansi.fg.yellow + truncate(entry.pid, COL.pid - 1) + ansi.reset, COL.pid) +
        ansi.fg.magenta + truncate(entry.processName, processMaxLen) + ansi.reset;
    }
    out.push(pad(line, w));
  }

  // Write output
  process.stdout.write(ansi.clear + ansi.hideCursor);
  for (let i = 0; i < out.length; i++) {
    process.stdout.write(ansi.moveTo(i + 1, 1) + out[i]);
  }

  // Sixel scrollbar overlay
  scrollbarOverlay = null;
  const maxScroll = getMaxScroll();
  if (maxScroll > 0 && cellW > 0 && cellH > 0) {
    const pixBuf = renderScrollbarPixels(cellW, cellH, dataRows, scrollOffset, maxScroll);
    if (pixBuf) {
      const palette = dragging === 'scrollbar' ? SCROLLBAR_ACTIVE_PALETTE : SCROLLBAR_PALETTE;
      const sixelStr = encodeSixel(pixBuf, cellW, dataRows * cellH, palette);
      const screenRow = 3;  // data area starts at row 3
      const screenCol = w;  // rightmost column
      scrollbarOverlay = { sixelStr, screenRow, screenCol, viewportRows: dataRows, maxScroll };
      process.stdout.write(ansi.moveTo(screenRow, screenCol) + sixelStr);
    }
  }
}

function computeColumns(totalWidth) {
  // Minimum columns with padding
  const proto = 8;
  const pid = 8;
  const state = 15;
  const remaining = totalWidth - proto - pid - state - 2; // 2 for leading spaces
  const local = Math.max(16, Math.floor(remaining * 0.38));
  const remote = Math.max(16, Math.floor(remaining * 0.38));
  // process gets the rest
  return { proto, local, remote, state, pid };
}

// ============================================================
// 7. Context Menu
// ============================================================
let currentMenuZone = null;

function getMenuZone(row) {
  if (row === 1) return 'colheader';
  if (row >= 3 && row <= 2 + getDataRowCount()) return 'data';
  return null;
}

function getMenuItems(zone) {
  if (zone === 'colheader') {
    return [
      { id: 'sort_proto',   label: 'Sort by Protocol' + (sortColumn === 'proto' ? (sortAsc ? ' \u25B2' : ' \u25BC') : ''), icon: 'arrow-swap' },
      { id: 'sort_local',   label: 'Sort by Local Address' + (sortColumn === 'local' ? (sortAsc ? ' \u25B2' : ' \u25BC') : ''), icon: 'arrow-swap' },
      { id: 'sort_remote',  label: 'Sort by Remote Address' + (sortColumn === 'remote' ? (sortAsc ? ' \u25B2' : ' \u25BC') : ''), icon: 'arrow-swap' },
      { id: 'sort_state',   label: 'Sort by State' + (sortColumn === 'state' ? (sortAsc ? ' \u25B2' : ' \u25BC') : ''), icon: 'arrow-swap' },
      { id: 'sort_pid',     label: 'Sort by PID' + (sortColumn === 'pid' ? (sortAsc ? ' \u25B2' : ' \u25BC') : ''), icon: 'arrow-swap' },
      { id: 'sort_process', label: 'Sort by Process' + (sortColumn === 'process' ? (sortAsc ? ' \u25B2' : ' \u25BC') : ''), icon: 'arrow-swap' },
      { type: 'separator' },
      { id: 'filter_state', label: 'State Filter', icon: 'filter', children:
        STATES.map(s => ({
          id: 'state_' + s,
          label: s,
          checked: STATES[stateFilterIdx] === s,
        }))
      },
      { id: 'filter_proto', label: 'Protocol Filter', icon: 'filter', children:
        PROTOS.map(p => ({
          id: 'proto_' + p,
          label: p,
          checked: PROTOS[protoFilterIdx] === p,
        }))
      },
      { id: 'search', label: 'Search...', icon: 'search', shortcut: '/' },
      { id: 'clear_filters', label: 'Clear Filters', icon: 'clear-all' },
      { type: 'separator' },
      { id: 'auto_toggle', label: `Auto Refresh: ${autoRefresh ? 'ON' : 'OFF'}`, icon: 'sync', checked: autoRefresh },
      { id: 'refresh', label: 'Refresh', icon: 'refresh', shortcut: 'r' },
    ];
  }
  if (zone === 'data') {
    const entry = filteredEntries[selectedIndex];
    const items = [];
    if (entry) {
      const pidLabel = entry.processName
        ? `Kill ${entry.processName} (PID ${entry.pid})`
        : `Kill PID ${entry.pid}`;
      items.push({ id: 'kill', label: pidLabel, icon: 'close' });
      items.push({ type: 'separator' });
      items.push({ id: 'copy_line', label: 'Copy Line', icon: 'clippy', shortcut: 'c' });
      items.push({ id: 'copy_port', label: `Copy Port (${extractPort(entry.localAddr)})`, icon: 'clippy' });
      items.push({ id: 'copy_addr', label: `Copy Address (${entry.localAddr})`, icon: 'clippy' });
    }
    items.push({ type: 'separator' });
    items.push({ id: 'refresh', label: 'Refresh', icon: 'refresh', shortcut: 'r' });
    return items;
  }
  return [];
}

function extractPort(addr) {
  if (!addr) return '';
  const lastColon = addr.lastIndexOf(':');
  if (lastColon === -1) return addr;
  return addr.substring(lastColon + 1);
}

function updateMenuForZone(zone) {
  if (zone === currentMenuZone) return;
  currentMenuZone = zone;
  const items = zone ? getMenuItems(zone) : [];
  sendRpc('register_context_menu', { items });
}

function refreshContextMenu() {
  // Force re-register current zone menu
  const zone = currentMenuZone;
  currentMenuZone = null;
  updateMenuForZone(zone);
}

async function handleMenuAction(actionId) {
  // State filter actions
  if (actionId.startsWith('state_')) {
    const state = actionId.substring(6);
    stateFilterIdx = STATES.indexOf(state);
    if (stateFilterIdx < 0) stateFilterIdx = 0;
    applyFilterAndSort();
    refreshContextMenu();
    rerender();
    return;
  }
  // Protocol filter actions
  if (actionId.startsWith('proto_')) {
    const proto = actionId.substring(6);
    protoFilterIdx = PROTOS.indexOf(proto);
    if (protoFilterIdx < 0) protoFilterIdx = 0;
    applyFilterAndSort();
    refreshContextMenu();
    rerender();
    return;
  }
  // Sort actions
  if (actionId.startsWith('sort_')) {
    const col = actionId.substring(5);
    if (sortColumn === col) {
      sortAsc = !sortAsc;
    } else {
      sortColumn = col;
      sortAsc = true;
    }
    applyFilterAndSort();
    refreshContextMenu();
    rerender();
    return;
  }

  switch (actionId) {
    case 'refresh':
      collectPortData();
      break;
    case 'auto_toggle':
      toggleAutoRefresh();
      break;
    case 'search':
      showSearchDialog();
      break;
    case 'clear_filters':
      stateFilterIdx = 0;
      protoFilterIdx = 0;
      searchQuery = '';
      applyFilterAndSort();
      refreshContextMenu();
      rerender();
      break;
    case 'kill':
      killSelectedProcess();
      break;
    case 'copy_line':
      copySelectedLine();
      break;
    case 'copy_port':
      copySelectedPort();
      break;
    case 'copy_addr':
      copySelectedAddr();
      break;
  }
}

// ============================================================
// 8. Input Handling
// ============================================================
function handleInput(data) {
  const str = data.toString();

  // Host RPC messages
  if (str.indexOf('__HECA_RPC__') !== -1) {
    const segments = str.split('__HECA_RPC__');
    for (const seg of segments) {
      const trimmed = seg.trim();
      if (!trimmed) continue;
      try {
        const json = JSON.parse(trimmed);

        // RPC response
        if (json.id != null && (json.result || json.error)) {
          handleRpcResponse(json);
          continue;
        }

        // Host notifications
        if (json.method === 'resize' && json.params) {
          termCols = json.params.cols || termCols;
          termRows = json.params.rows || termRows;
          if (json.params.cellWidth) cellW = Math.round(json.params.cellWidth);
          if (json.params.cellHeight) cellH = Math.round(json.params.cellHeight);
          clampScroll();
          rerender();
        }
        if (json.method === 'minimize') {
          minimized = true;
          rerender();
        }
        if (json.method === 'restore') {
          minimized = false;
          rerender();
        }
        if (json.method === 'maximize') {
          rerender();
        }
        if (json.method === 'context_menu_action' && json.params) {
          handleMenuAction(json.params.id);
        }
        if (json.method === 'dialog_result' && json.params) {
          handleDialogResult(json.params);
        }
      } catch { /* ignore parse errors */ }
    }
    return;
  }

  // SGR mouse events: ESC[<Cb;Cx;CyM (press) or ESC[<Cb;Cx;Cym (release)
  const mouseMatch = str.match(/\x1b\[<(\d+);(\d+);(\d+)([Mm])/);
  if (mouseMatch) {
    const cb = parseInt(mouseMatch[1], 10);
    const cx = parseInt(mouseMatch[2], 10);
    const cy = parseInt(mouseMatch[3], 10);
    const pressed = mouseMatch[4] === 'M';
    const btn = cb & 3;
    const motion = !!(cb & 32);
    const wheel = !!(cb & 64);

    // Update context menu zone
    updateMenuForZone(getMenuZone(cy));

    // Release → end drag
    if (!pressed && !wheel) {
      if (dragging === 'scrollbar') {
        dragging = null;
        scrollbarDragInfo = null;
        rerender();
      }
      return;
    }

    // Scrollbar drag in progress (motion while dragging)
    if (motion && dragging === 'scrollbar' && scrollbarDragInfo) {
      const relY = cy - scrollbarDragInfo.trackTop;
      const ratio = Math.max(0, Math.min(1, relY / Math.max(1, scrollbarDragInfo.trackH - 1)));
      scrollOffset = Math.round(ratio * scrollbarDragInfo.maxScroll);
      const dataRows = getDataRowCount();
      if (selectedIndex < scrollOffset) selectedIndex = scrollOffset;
      if (selectedIndex >= scrollOffset + dataRows) selectedIndex = scrollOffset + dataRows - 1;
      if (selectedIndex >= filteredEntries.length) selectedIndex = filteredEntries.length - 1;
      rerender();
      return;
    }

    // Left click or Right click on data row → select
    if (pressed && !motion && !wheel && (btn === 0 || btn === 2)) {
      // Scrollbar click (left only)
      if (btn === 0 && scrollbarOverlay && cx === scrollbarOverlay.screenCol &&
          cy >= scrollbarOverlay.screenRow && cy < scrollbarOverlay.screenRow + scrollbarOverlay.viewportRows) {
        dragging = 'scrollbar';
        scrollbarDragInfo = {
          trackTop: scrollbarOverlay.screenRow,
          trackH: scrollbarOverlay.viewportRows,
          maxScroll: scrollbarOverlay.maxScroll,
        };
        const relY = cy - scrollbarOverlay.screenRow;
        const ratio = Math.max(0, Math.min(1, relY / Math.max(1, scrollbarOverlay.viewportRows - 1)));
        scrollOffset = Math.round(ratio * scrollbarOverlay.maxScroll);
        const dataRows = getDataRowCount();
        if (selectedIndex < scrollOffset) selectedIndex = scrollOffset;
        if (selectedIndex >= scrollOffset + dataRows) selectedIndex = scrollOffset + dataRows - 1;
        if (selectedIndex >= filteredEntries.length) selectedIndex = filteredEntries.length - 1;
        rerender();
        return;
      }

      // Data row click → select
      const dataStartRow = 3;
      const clickedDataIdx = cy - dataStartRow + scrollOffset;
      if (cy >= dataStartRow && cy < dataStartRow + getDataRowCount() && clickedDataIdx >= 0 && clickedDataIdx < filteredEntries.length) {
        selectedIndex = clickedDataIdx;
        refreshContextMenu();
        rerender();
      }
    }

    // Scroll wheel
    if (wheel && pressed) {
      const maxScroll = getMaxScroll();
      const dataRows = getDataRowCount();
      if (btn === 0) {
        scrollOffset = Math.max(0, scrollOffset - 3);
      } else {
        scrollOffset = Math.min(maxScroll, scrollOffset + 3);
      }
      // Keep selectedIndex within visible range
      if (selectedIndex < scrollOffset) selectedIndex = scrollOffset;
      if (selectedIndex >= scrollOffset + dataRows) selectedIndex = scrollOffset + dataRows - 1;
      if (selectedIndex >= filteredEntries.length) selectedIndex = filteredEntries.length - 1;
      rerender();
    }
    return;
  }

  // Escape sequences (arrow keys, PgUp/PgDn, Home/End, etc.)
  const escMatch = str.match(/\x1b(\[|O)([0-9;]*)(.)/);
  if (escMatch) {
    const params = escMatch[2];
    const final = escMatch[3];
    const parts = params.split(';');

    // Arrow keys / navigation (no modifier)
    const arrowKeys = { A: 'Up', B: 'Down', H: 'Home', F: 'End' };
    const tildeKeys = { '5': 'PageUp', '6': 'PageDown' };

    if (arrowKeys[final]) {
      switch (final) {
        case 'A': // Up
          if (selectedIndex > 0) {
            selectedIndex--;
            clampScroll();
            refreshContextMenu();
            rerender();
          }
          break;
        case 'B': // Down
          if (selectedIndex < filteredEntries.length - 1) {
            selectedIndex++;
            clampScroll();
            refreshContextMenu();
            rerender();
          }
          break;
        case 'H': // Home
          selectedIndex = 0;
          scrollOffset = 0;
          refreshContextMenu();
          rerender();
          break;
        case 'F': // End
          selectedIndex = Math.max(0, filteredEntries.length - 1);
          clampScroll();
          refreshContextMenu();
          rerender();
          break;
      }
      return;
    }
    if (final === '~' && parts[0]) {
      const key = tildeKeys[parts[0]];
      if (key === 'PageUp') {
        const pageSize = getDataRowCount();
        selectedIndex = Math.max(0, selectedIndex - pageSize);
        clampScroll();
        refreshContextMenu();
        rerender();
        return;
      }
      if (key === 'PageDown') {
        const pageSize = getDataRowCount();
        selectedIndex = Math.min(filteredEntries.length - 1, selectedIndex + pageSize);
        clampScroll();
        refreshContextMenu();
        rerender();
        return;
      }
    }
    return;
  }

  // Standalone ESC
  if (str === ESC) {
    cleanup();
    process.exit(0);
  }

  // Character input
  for (const ch of str) {
    const code = ch.charCodeAt(0);

    // Skip control chars except specific ones
    if (code < 0x20 && code !== 0x0D && code !== 0x09) continue;
    if (code === 0x7F) continue; // backspace

    switch (ch) {
      case 'r': case 'R':
        collectPortData();
        break;
      case '/':
        showSearchDialog();
        break;
      case 'f': case 'F':
        stateFilterIdx = (stateFilterIdx + 1) % STATES.length;
        applyFilterAndSort();
        refreshContextMenu();
        rerender();
        break;
      case 'p':
        protoFilterIdx = (protoFilterIdx + 1) % PROTOS.length;
        applyFilterAndSort();
        refreshContextMenu();
        rerender();
        break;
      case 'k': case 'K':
        killSelectedProcess();
        break;
      case 'a': case 'A':
        toggleAutoRefresh();
        break;
      case 'c': case 'C':
        copySelectedLine();
        break;
    }
  }
}

// ============================================================
// 9. Actions
// ============================================================
async function showSearchDialog() {
  const result = await sendRpc('show_dialog', {
    type: 'input',
    title: 'Search Ports',
    message: 'Enter search query (matches proto, address, state, PID, process):',
    defaultValue: searchQuery,
    buttons: [
      { id: 'ok', label: 'Search' },
      { id: 'clear', label: 'Clear' },
      { id: 'cancel', label: 'Cancel' },
    ],
  });
  // result handled in dialog_result notification
}

function handleDialogResult(params) {
  const { buttonId, value } = params;

  // Search dialog
  if (buttonId === 'ok' && value != null) {
    searchQuery = value;
    applyFilterAndSort();
    rerender();
    return;
  }
  if (buttonId === 'clear') {
    searchQuery = '';
    applyFilterAndSort();
    rerender();
    return;
  }

  // Kill confirmation
  if (buttonId === 'kill_confirm') {
    const entry = filteredEntries[selectedIndex];
    if (entry && entry.pid && entry.pid !== '0' && entry.pid !== '4') {
      try {
        execSync(`taskkill /PID ${entry.pid} /F`, {
          encoding: 'utf-8',
          timeout: 5000,
          windowsHide: true,
        });
      } catch { /* process may already be gone */ }
      // Refresh after kill
      setTimeout(() => { collectPortData(); }, 500);
    }
  }
}

async function killSelectedProcess() {
  const entry = filteredEntries[selectedIndex];
  if (!entry) return;

  // Protect system processes
  if (entry.pid === '0' || entry.pid === '4') {
    await sendRpc('show_dialog', {
      type: 'message',
      title: 'Cannot Kill',
      message: `PID ${entry.pid} is a system process and cannot be terminated.`,
      buttons: [{ id: 'ok', label: 'OK' }],
    });
    return;
  }

  const name = entry.processName || 'Unknown';
  await sendRpc('show_dialog', {
    type: 'message',
    title: 'Kill Process',
    message: `Terminate ${name} (PID ${entry.pid})?\n\nLocal: ${entry.localAddr}\nRemote: ${entry.remoteAddr}\nState: ${entry.state || 'N/A'}`,
    buttons: [
      { id: 'kill_confirm', label: 'Kill' },
      { id: 'cancel', label: 'Cancel' },
    ],
  });
}

async function copySelectedLine() {
  const entry = filteredEntries[selectedIndex];
  if (!entry) return;
  const line = `${entry.proto}\t${entry.localAddr}\t${entry.remoteAddr}\t${entry.state}\t${entry.pid}\t${entry.processName}`;
  await sendRpc('write_clipboard', { text: line });
}

async function copySelectedPort() {
  const entry = filteredEntries[selectedIndex];
  if (!entry) return;
  const port = extractPort(entry.localAddr);
  await sendRpc('write_clipboard', { text: port });
}

async function copySelectedAddr() {
  const entry = filteredEntries[selectedIndex];
  if (!entry) return;
  await sendRpc('write_clipboard', { text: entry.localAddr });
}

function toggleAutoRefresh() {
  autoRefresh = !autoRefresh;
  if (autoRefresh) {
    startAutoRefresh();
  } else {
    stopAutoRefresh();
  }
  refreshContextMenu();
  rerender();
}

function startAutoRefresh() {
  stopAutoRefresh();
  autoRefreshTimer = setInterval(() => {
    collectPortData();
  }, AUTO_REFRESH_INTERVAL);
}

function stopAutoRefresh() {
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }
}

// ============================================================
// 10. Main
// ============================================================
function cleanup() {
  stopAutoRefresh();
  process.stdout.write(ansi.showCursor + ansi.reset + ansi.clear);
}

async function main() {
  // Render immediately (empty data), then collect asynchronously
  render();

  // Fetch cell size for sixel scrollbar
  try {
    const cellSizeResult = await sendRpc('get_cell_size');
    if (cellSizeResult && cellSizeResult.cellWidth && cellSizeResult.cellHeight) {
      cellW = Math.round(cellSizeResult.cellWidth);
      cellH = Math.round(cellSizeResult.cellHeight);
    }
  } catch { /* use defaults */ }

  // Collect data in background — rerender() called when done
  collectPortData();

  // Start auto refresh
  if (autoRefresh) startAutoRefresh();

  // Input setup
  try {
    if (process.stdin.isTTY) process.stdin.setRawMode(true);
  } catch { /* not a TTY */ }
  process.stdin.resume();
  process.stdin.setEncoding('utf-8');
  process.stdin.on('data', handleInput);

  process.on('SIGTERM', () => { cleanup(); process.exit(0); });
  process.on('SIGINT', () => { cleanup(); process.exit(0); });
  process.stdin.on('end', () => { cleanup(); process.exit(0); });
}

main();
