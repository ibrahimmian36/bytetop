/* Dashboard composition for bytetop. Same layout idioms as
 * xtop / blktop / flowtop / airtop: top rule, content strips, zip()'d
 * split row — but the panels are tuned for traffic accounting.
 *
 * The signature view is the TRAFFIC BY DESTINATION panel: every
 * remote endpoint visible to the kernel right now, sorted by current
 * bandwidth, color-coded by encryption posture, with a tx/rx visual.
 * Encrypted ports (443/22/8443/…) render in green; cleartext ports
 * (80/53/3306/…) in yellow. That tells you at a glance whether any
 * app on this box is shipping data in the clear. */

import {
  fg, bold, dim, ital, RESET, EOL,
  HEAT_TX, HEAT_RX, EIGHTH,
  C_AXIS, C_DIM, C_ENC, C_PLAIN, C_OTHER, C_TX, C_RX, C_ALERT,
  portClass, portColor, portMark,
  formatBytes, formatBps, compactNum,
  fmtEndpoint, mmss, fmtAge,
  vlen, clipAnsi, fixw, padVis,
  sparkline, hbar, heatCell,
} from "./render.js";

import {
  tot, txHist, rxHist, opensHist, activeHist,
  liveRates, topProcs, topDests, recentEvents,
  aName, aAddr, startTime,
  TICK_MS, WINDOW_MS,
} from "./state.js";

const MIN_COLS = 80;
const MIN_ROWS = 28;

/* ---- chrome helpers (mirror sibling projects) ---------------------- */
function topRule(C, title) {
  const head = ` ▌ ${title} `;
  return bold + fg(C_TX) + head + RESET + fg(C_AXIS) +
    "─".repeat(Math.max(0, C - head.length)) + RESET + EOL;
}
function botRule(C) { return fg(C_AXIS) + "─".repeat(C) + RESET + EOL; }
function sectionBar(C, text) {
  /* Format is: "  TEXT ────…". When text alone overruns C, we clip the
   * whole line to C visible cells via clipAnsi so we never emit an
   * over-width line. */
  const prefix = fg(45) + "  " + text + " ";
  const tail = fg(C_AXIS) + "─".repeat(Math.max(0, C - vlen(prefix))) + RESET;
  return clipAnsi(prefix + tail, C) + EOL;
}
function sectionTitle(lw, left, right) {
  return `${fg(45)}${left}${" ".repeat(Math.max(1, lw - left.length))}${fg(C_AXIS)}│ ` +
    `${fg(45)}${right}${RESET}${EOL}`;
}
function zip(L, R, lw, rw, rows) {
  const h = Math.max(L.length, R.length);
  const bl = " ".repeat(lw), br = " ".repeat(rw);
  for (let i = 0; i < h; i++)
    rows.push(`${L[i] ?? bl}${fg(C_AXIS)}│${RESET} ${R[i] ?? br}${EOL}`);
}

/* ---- header line --------------------------------------------------- */
function headerLine(C) {
  const r = liveRates();
  const live = bold + fg(46) + "●" + RESET + fg(252) + " LIVE " + RESET;
  const up = fg(C_DIM) + mmss(Date.now() - startTime) + RESET;
  const active = fg(252) + compactNum(r.active) + RESET + fg(C_DIM) + " active" + RESET;
  const tx = fg(C_TX) + "▲ " + RESET + fg(252) + formatBps(r.tx_bps) + RESET;
  const rx = fg(C_RX) + "▼ " + RESET + fg(252) + formatBps(r.rx_bps) + RESET;
  /* encrypted share: percent of current tx+rx bytes that flowed on
   * known-encrypted ports */
  const total = r.tx_bps + r.rx_bps;
  const enc = r.tx_enc_bps + r.rx_enc_bps;
  const pct = total > 0 ? Math.round((enc / total) * 100) : 100;
  const encColor = pct >= 95 ? C_ENC : pct >= 75 ? C_PLAIN : C_ALERT;
  const encStr = fg(encColor) + (pct + "% enc") + RESET;
  /* opens-per-sec */
  const opensPerSec = opensHist.length > 0
    ? opensHist.slice(-5).reduce((a, b) => a + b, 0)
    : 0;
  const opens = fg(C_DIM) + compactNum(opensPerSec) + "/s open" + RESET;
  /* compact variants for narrow terminals */
  const tight = " ";
  const SEP   = fg(C_DIM) + "   " + RESET;
  const parts = [live + up, active, tx + " " + rx, encStr, opens];
  let line = parts.join(SEP);
  if (vlen(line) > C) line = parts.join(tight);
  return clipAnsi(line, C) + EOL;
}

/* ---- panel: traffic by destination (SIGNATURE) --------------------
 * Each row: glyph + endpoint + tx bar + rx bar + counts + sparkline.
 * Endpoint colored by port class so encrypted (green) / plain (yellow)
 * are immediately distinguishable. Width adaptive: narrow terminals
 * drop the sparkline column; very narrow drop the dual bars. */
function panelDestinations(C, H) {
  const list = topDests(H);
  if (list.length === 0) {
    return [fg(C_DIM) + ital + "  no destinations yet — open a connection on this box to populate." + RESET];
  }
  const ENDP_W   = Math.min(28, Math.max(20, Math.floor(C * 0.30)));
  const RATE_W   = 10;                /* "999MB/s  " */
  const COUNT_W  = 10;                /* "999 conn" */
  const showSpark = C >= 100;
  const showBars  = C >= 78;
  const sparkW   = showSpark ? Math.max(8, C - (2 + 1 + ENDP_W + 1 + RATE_W*2 + 2 + (showBars ? 16 : 0) + COUNT_W + 4)) : 0;

  /* derive a shared bandwidth ceiling for the bars so they're
   * comparable across rows. Use 2× the top dest's tx+rx for headroom. */
  const top = list[0];
  const ceiling = Math.max(1, (top.tx_bps + top.rx_bps) * 2);
  const barW = showBars ? 7 : 0;

  const out = [];
  for (const item of list) {
    if (out.length >= H) break;
    const d = item.d;
    const cls = d.cls;
    const ec = cls === "enc" ? C_ENC : cls === "plain" ? C_PLAIN : C_OTHER;
    const mark = fg(ec) + portMark(d.port) + RESET;
    const ep = aAddr(fmtEndpoint(d.family, d.addr, d.port));
    const epCell = fixw(fg(ec) + ep + RESET, ENDP_W);
    const txRate = fg(C_TX) + "▲" + RESET + fixw(formatBps(item.tx_bps), RATE_W - 1);
    const rxRate = fg(C_RX) + "▼" + RESET + fixw(formatBps(item.rx_bps), RATE_W - 1);
    let bars = "";
    if (showBars) {
      bars = " " + hbar(item.tx_bps, ceiling, barW, C_TX) + " " +
                   hbar(item.rx_bps, ceiling, barW, C_RX);
    }
    const counts = fg(C_DIM) + fixw(compactNum(d.conn_count) + " conn", COUNT_W) + RESET;
    let spark = "";
    if (showSpark && sparkW >= 4) {
      const txS = sparkline(d.tx_rate_hist, sparkW, C_TX);
      spark = " " + txS;
    }
    const line = " " + mark + " " + epCell + " " + txRate + "  " + rxRate + bars + " " + counts + spark;
    out.push(clipAnsi(line, C));
  }
  while (out.length < H) out.push(" ".repeat(C));
  return out;
}

/* ---- panel: total bandwidth chart ---------------------------------
 * A heatmap-style strip showing recent total tx (upper half) and rx
 * (lower half) over the visible window. Each column is one tick. */
function panelBandwidthHeat(C, H) {
  const labelW = 14;          /* fits "▲ tx 1023KB/s" without overflow */
  const sepW = 2;             /* " │" */
  const stripW = C - labelW - sepW;
  if (stripW < 10 || H < 4) return [" ".repeat(C)];

  /* split rows roughly half tx, half rx */
  const txRows = Math.floor(H / 2);
  const rxRows = H - txRows;

  /* find the global max across both directions in the visible window */
  const visTicks = Math.min(stripW, Math.max(txHist.length, rxHist.length));
  const txStart = Math.max(0, txHist.length - visTicks);
  const rxStart = Math.max(0, rxHist.length - visTicks);
  let max = 0;
  for (let i = txStart; i < txHist.length; i++) if (txHist[i] > max) max = txHist[i];
  for (let i = rxStart; i < rxHist.length; i++) if (rxHist[i] > max) max = rxHist[i];

  const out = [];

  /* tx rows: top is brightest, bottom is dimmest — column intensity
   * is the bytes-per-tick scaled into [0,1] over the global max. */
  for (let r = 0; r < txRows; r++) {
    const thresh = (txRows - r) / (txRows + 1);
    let strip = "";
    const lead = stripW - visTicks;
    for (let i = 0; i < lead; i++) strip += heatCell(-1);
    for (let i = 0; i < visTicks; i++) {
      const v = (txHist[txStart + i] ?? 0) / (max || 1);
      strip += v >= thresh ? heatCell(Math.min(1, v), HEAT_TX) : heatCell(-1);
    }
    const lbl = (r === 0)
      ? fg(C_TX) + "▲ tx " + RESET + fg(C_DIM) + formatBps(max) + RESET
      : "";
    const axis = fixw(lbl, labelW) + fg(C_AXIS) + " │" + RESET;
    out.push(axis + strip + EOL);
  }
  /* rx rows */
  for (let r = 0; r < rxRows; r++) {
    const thresh = (r + 1) / (rxRows + 1);
    let strip = "";
    const lead = stripW - visTicks;
    for (let i = 0; i < lead; i++) strip += heatCell(-1);
    for (let i = 0; i < visTicks; i++) {
      const v = (rxHist[rxStart + i] ?? 0) / (max || 1);
      strip += v >= thresh ? heatCell(Math.min(1, v), HEAT_RX) : heatCell(-1);
    }
    const lbl = (r === rxRows - 1)
      ? fg(C_RX) + "▼ rx " + RESET + fg(C_DIM) + formatBps(max) + RESET
      : "";
    const axis = fixw(lbl, labelW) + fg(C_AXIS) + " │" + RESET;
    out.push(axis + strip + EOL);
  }
  return out;
}

/* ---- panel: top processes ----------------------------------------- */
function panelTopProcs(W, H) {
  const list = topProcs(H);
  if (list.length === 0) {
    return [fg(C_DIM) + ital + "  no process-attributed traffic yet…" + RESET];
  }
  const showDests = W >= 38;
  const commW = Math.min(15, Math.max(10, W - 32));
  const out = [];
  for (let i = 0; i < Math.min(H, list.length); i++) {
    const it = list[i];
    const p = it.p;
    const comm = fixw(fg(252) + aName(p.comm) + RESET, commW);
    const pid = fg(C_DIM) + ("pid " + p.pid).padEnd(9) + RESET;
    const tx = fg(C_TX) + fixw(formatBps(it.tx_bps), 9) + RESET;
    const rx = fg(C_RX) + fixw(formatBps(it.rx_bps), 9) + RESET;
    const ds = showDests ? "  " + fg(C_DIM) + p.dests.size + " dest" + RESET : "";
    const line = comm + " " + pid + " " + tx + " " + rx + ds;
    out.push(clipAnsi(line, W));
  }
  while (out.length < H) out.push(" ".repeat(W));
  return out;
}

/* ---- panel: live event feed --------------------------------------- */
function panelFeed(C, H) {
  const list = recentEvents(H);
  if (list.length === 0) {
    return [fg(C_DIM) + ital + "  no events yet…" + RESET];
  }
  const epW = Math.max(20, Math.min(28, Math.floor((C - 50) / 2)));
  const out = [];
  for (let i = 0; i < Math.min(H, list.length); i++) {
    const e = list[i];
    const ts = fg(C_DIM) + mmss(Math.max(0, e.ts - startTime)) + RESET;
    const ec = portColor(e.dport);
    const mark = fg(ec) + portMark(e.dport) + RESET;
    const local = aAddr(fmtEndpoint(e.family, e.saddr, e.sport));
    const remote = aAddr(fmtEndpoint(e.family, e.daddr, e.dport));
    let middle;
    if (e.kind === "open") {
      middle = fg(ec) + bold + fixw("● OPEN", 8) + RESET + " " +
               fg(252) + fixw(local, epW) + RESET +
               fg(C_DIM) + " → " + RESET +
               fg(ec) + fixw(remote, epW) + RESET;
    } else /* close */ {
      const bytes = fg(C_DIM) + fixw(
        formatBytes(e.bytes_tx) + "/" + formatBytes(e.bytes_rx),
        16) + RESET;
      middle = fg(C_DIM) + fixw("✕ CLOSE", 8) + RESET + " " +
               fg(252) + fixw(local, epW) + RESET +
               fg(C_DIM) + " → " + RESET +
               fg(248) + fixw(remote, epW) + RESET +
               " " + bytes;
    }
    const proc = (e.pid > 0)
      ? fg(C_DIM) + "  pid " + e.pid + " " + RESET + fg(248) + aName(e.comm) + RESET
      : "";
    const line = " " + ts + "  " + mark + " " + middle + proc;
    out.push(clipAnsi(line, C));
  }
  while (out.length < H) out.push(" ".repeat(C));
  return out;
}

/* ---- composition --------------------------------------------------- */
export function renderDashboard(C, R) {
  if (C < MIN_COLS || R < MIN_ROWS) return smallTerm(C, R);

  const rows = [];
  rows.push(topRule(C, "BYTETOP · per-process per-destination traffic observatory"));
  rows.push(headerLine(C));
  rows.push("");

  const winSec = Math.round(WINDOW_MS / 1000);
  const showMid = R >= 32;

  /* chrome accounting (everything that isn't a content strip):
   *  top + header + blank + dest-title + dest-rows
   *  + blank + bw-title + bw-rows
   *  + (mid ? blank + mid-title + midRows : 0)
   *  + blank + feed-title + feed-rows
   *  + bottom-rule */
  const chrome = 2 /* top+header */ + 1
               + 1 /* dest title */
               + 1 + 1 /* blank + bw title */
               + (showMid ? 1 + 1 : 0)
               + 1 + 1 /* blank + feed title */
               + 1 /* bottom rule */;

  const content = R - chrome;
  const destH = Math.max(5, Math.round(content * 0.36));
  const bwH   = Math.max(4, Math.round(content * 0.22));
  const midH  = showMid ? Math.max(3, Math.round(content * 0.20)) : 0;
  const feedH = Math.max(3, content - destH - bwH - midH);

  /* signature: traffic by destination */
  rows.push(sectionBar(C, "TRAFFIC BY DESTINATION · " +
                            fg(C_ENC) + "● enc" + fg(45) + "  " +
                            fg(C_PLAIN) + "○ plain" + fg(45) + "  " +
                            fg(C_OTHER) + "· other" + fg(45)));
  const dx = panelDestinations(C, destH);
  for (let i = 0; i < destH; i++) rows.push(dx[i] ?? " ".repeat(C));

  /* bandwidth heatmap */
  rows.push("");
  rows.push(sectionBar(C, "TOTAL BANDWIDTH · " + formatBytes(tot.bytes_tx) + " ▲ sent · " +
                          formatBytes(tot.bytes_rx) + " ▼ received cumulative"));
  const bw = panelBandwidthHeat(C, bwH);
  for (let i = 0; i < bwH; i++) rows.push(bw[i] ?? " ".repeat(C));

  /* mid: top procs (full-width — no split needed; the dest panel above
   * is already the wide one) */
  if (showMid) {
    rows.push("");
    rows.push(sectionBar(C, "TOP PROCESSES · " + winSec + "s window"));
    const tp = panelTopProcs(C, midH);
    for (let i = 0; i < midH; i++) rows.push(tp[i] ?? " ".repeat(C));
  }

  /* live feed */
  rows.push("");
  rows.push(sectionBar(C, "CONNECTION FEED · opens and closes, newest first"));
  const fd = panelFeed(C, feedH);
  for (let i = 0; i < feedH; i++) rows.push(fd[i] ?? " ".repeat(C));

  rows.push(botRule(C));

  /* ensure each row ends with EOL; clip overall to R */
  const trimmed = rows.slice(0, R).map(
    (l) => (l && (l.endsWith(EOL) || l.includes("\x1b[K"))) ? l : l + EOL);
  return clearScreen() + trimmed.join("\n");
}

export function clearScreen() { return "\x1b[H\x1b[2J"; }

function smallTerm(C, R) {
  const lines = [
    `bytetop: terminal too small`,
    `need ≥ ${MIN_COLS}×${MIN_ROWS}`,
    `have ${C}×${R}`,
  ];
  return lines.map((l) => l.slice(0, Math.max(1, C))).join("\n") + "\n";
}
