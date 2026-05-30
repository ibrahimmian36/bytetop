/* Pure terminal-rendering toolkit for bytetop: ANSI escapes, color
 * ramps, a braille canvas, address/port/byte formatters, and the
 * encrypted-vs-plaintext palette. No application state, no I/O — safe
 * to import anywhere. */

export const ESC = "\x1b[";
export const HOME = `${ESC}H`;
export const CLEAR = `${ESC}2J${ESC}H`;
export const HIDE = `${ESC}?25l`;
export const SHOW = `${ESC}?25h`;
export const RESET = `${ESC}0m`;
export const EOL = `${ESC}K`;
export const bold = `${ESC}1m`;
export const dim = `${ESC}2m`;
export const ital = `${ESC}3m`;
export const fg = (n) => `${ESC}38;5;${n}m`;
export const bg = (n) => `${ESC}48;5;${n}m`;

/* low → high "heat" ramp, used for tx and rx intensity. */
export const HEAT_TX = [17, 18, 19, 20, 26, 32, 39, 45, 51, 50, 48, 46, 82, 118];
export const HEAT_RX = [52, 88, 124, 160, 196, 202, 208, 214, 220, 226, 190, 154, 118, 82];
export const SILENT_BG = 234;
export const EIGHTH = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

/* role colors */
export const C_AXIS  = 238;
export const C_DIM   = 240;
export const C_ENC   = 84;     /* encrypted / trusted protocols — green */
export const C_PLAIN = 220;    /* plaintext / cleartext — yellow (caution) */
export const C_OTHER = 244;    /* unknown / generic — neutral gray */
export const C_TX    = 51;     /* outbound bytes — cyan */
export const C_RX    = 215;    /* inbound bytes — orange */
export const C_ALERT = 196;    /* warnings — red */

/* ---- well-known port classification --------------------------------
 * A pragmatic table: anything that is overwhelmingly used to carry an
 * encrypted protocol (TLS, SSH, etc.) counts as "encrypted". Anything
 * still commonly used in cleartext counts as "plaintext". The rest are
 * "other" — we don't pretend to know. This drives the color coding
 * across the dashboard. */
const ENCRYPTED_PORTS = new Set([
  22,    /* SSH                    */
  443,   /* HTTPS                  */
  465,   /* SMTPS                  */
  563,   /* NNTPS                  */
  636,   /* LDAPS                  */
  853,   /* DNS-over-TLS           */
  989, 990, /* FTPS                */
  993,   /* IMAPS                  */
  995,   /* POP3S                  */
  1194,  /* OpenVPN                */
  4433, 4434, /* HTTPS alts        */
  5061,  /* SIPS                   */
  5223,  /* XMPP-over-TLS          */
  5349,  /* TURNS                  */
  5671,  /* AMQPS                  */
  6679, 6697, /* IRC-over-TLS      */
  8443, 8843, 9443, /* HTTPS alts  */
  9418,  /* Git                    */
  51820, /* WireGuard              */
]);
const PLAINTEXT_PORTS = new Set([
  21,    /* FTP control            */
  23,    /* Telnet                 */
  25,    /* SMTP                   */
  53,    /* DNS (mostly UDP, but TCP fallback / large responses) */
  69,    /* TFTP                   */
  80,    /* HTTP                   */
  110,   /* POP3                   */
  119,   /* NNTP                   */
  143,   /* IMAP                   */
  161,   /* SNMP                   */
  389,   /* LDAP                   */
  587,   /* SMTP submission        */
  3306,  /* MySQL (cleartext by default) */
  5432,  /* PostgreSQL (cleartext by default) */
  6379,  /* Redis  (cleartext by default) */
  11211, /* memcached              */
  27017, /* MongoDB (cleartext by default) */
]);
export function portClass(port) {
  if (ENCRYPTED_PORTS.has(port)) return "enc";
  if (PLAINTEXT_PORTS.has(port)) return "plain";
  /* High ephemeral ports (outgoing) we just treat as "other" — we use
   * the destination port for classification, which is what matters for
   * the encryption posture of the conversation. */
  return "other";
}
export function portColor(port) {
  switch (portClass(port)) {
    case "enc":   return C_ENC;
    case "plain": return C_PLAIN;
    default:      return C_OTHER;
  }
}
export function portGlyph(port) {
  switch (portClass(port)) {
    case "enc":   return "🔒";   /* lock glyph for trusted ports */
    case "plain": return "⚠";    /* caution for cleartext */
    default:      return "·";    /* neutral */
  }
}
/* Single-character ASCII fallback for terminals that don't render
 * emoji nicely. Same semantics as portGlyph, ASCII-only. */
export function portMark(port) {
  switch (portClass(port)) {
    case "enc":   return "●";
    case "plain": return "○";
    default:      return "·";
  }
}

/* ---- byte / rate formatters ---------------------------------------- */
const KB = 1024, MB = 1024 * 1024, GB = 1024 * 1024 * 1024, TB = 1024 * GB;
export function formatBytes(n) {
  if (!isFinite(n) || n < 0) return "—";
  if (n >= TB) return (n / TB).toFixed(n >= 10 * TB ? 0 : 1) + "TB";
  if (n >= GB) return (n / GB).toFixed(n >= 10 * GB ? 0 : 1) + "GB";
  if (n >= MB) return (n / MB).toFixed(n >= 10 * MB ? 0 : 1) + "MB";
  if (n >= KB) return (n / KB).toFixed(n >= 10 * KB ? 0 : 1) + "KB";
  return Math.round(n) + "B";
}
export function formatBps(bytesPerSec) {
  return formatBytes(bytesPerSec) + "/s";
}
export function compactNum(n) {
  if (!isFinite(n)) return "—";
  if (n >= 1e9) return (n / 1e9).toFixed(n >= 1e10 ? 0 : 1) + "G";
  if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + "M";
  if (n >= 1e4) return (n / 1e3).toFixed(0) + "k";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
  return String(Math.round(n));
}

/* ---- address formatters (mirror flowtop's) ------------------------- */
export function fmtIPv4(bytes) {
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}
export function fmtIPv6(bytes) {
  const g = new Array(8);
  for (let i = 0; i < 8; i++) g[i] = (bytes[i * 2] << 8) | bytes[i * 2 + 1];
  /* IPv4-mapped: ::ffff:a.b.c.d */
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 &&
      g[4] === 0 && g[5] === 0xffff) {
    return `::ffff:${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
  }
  /* find longest run of zeros (>= 2) to collapse */
  let bs = -1, bl = 0, cs = -1, cl = 0;
  for (let i = 0; i < 8; i++) {
    if (g[i] === 0) {
      if (cs === -1) { cs = i; cl = 1; } else cl++;
      if (cl > bl) { bs = cs; bl = cl; }
    } else { cs = -1; cl = 0; }
  }
  if (bl < 2) { bs = -1; bl = 0; }
  /* build the parts list with one slot for the collapse marker */
  const parts = [];
  for (let i = 0; i < 8; ) {
    if (i === bs) { parts.push(""); i += bl; continue; }
    parts.push(g[i].toString(16));
    i++;
  }
  /* If the collapse is at the start or end, that empty string is at
   * the boundary — joining with ":" naturally yields "::xxx" or
   * "xxx::". A collapse in the middle yields "xxx::yyy". */
  let s = parts.join(":");
  if (bs === 0) s = ":" + s;        /* leading "" + ":" + "rest" → ":rest", need "::rest" */
  if (bs + bl === 8) s = s + ":";   /* trailing "" + ":" already there at end via join, need extra ":" */
  return s;
}
export function fmtAddr(family, bytes) {
  return family === 10 /* AF_INET6 */ ? fmtIPv6(bytes) : fmtIPv4(bytes);
}
export function fmtEndpoint(family, bytes, port) {
  const addr = fmtAddr(family, bytes);
  return family === 10 ? `[${addr}]:${port}` : `${addr}:${port}`;
}

/* ---- time formatters ----------------------------------------------- */
export function mmss(ms) {
  const t = Math.floor(ms / 1000);
  const h = Math.floor(t / 3600);
  const m = Math.floor((t % 3600) / 60);
  const s = t % 60;
  const p = (n) => String(n).padStart(2, "0");
  return h > 0 ? `${p(h)}:${p(m)}:${p(s)}` : `${p(m)}:${p(s)}`;
}
export function fmtAge(ms) {
  if (!isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return Math.round(ms) + "ms";
  const s = Math.round(ms / 1000);
  if (s < 60) return s + "s";
  const m = Math.round(s / 60);
  if (m < 60) return m + "m";
  const h = Math.round(m / 60);
  return h + "h";
}

/* ---- visible-length-aware string ops ------------------------------- */
export function vlen(s) {
  return String(s).replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "").length;
}
export function clipAnsi(s, n) {
  let out = "", vis = 0, i = 0;
  while (i < s.length) {
    if (s[i] === "\x1b") {
      const m = /^\x1b\[[0-9;?]*[A-Za-z]/.exec(s.slice(i));
      if (m) { out += m[0]; i += m[0].length; continue; }
    }
    if (vis >= n) break;
    out += s[i]; vis++; i++;
  }
  return out + RESET;
}
export function fixw(s, w) {
  const v = vlen(s);
  if (v < w) s = s + " ".repeat(w - v);
  return clipAnsi(s, w);
}
export function padVis(s, n) {
  const pad = n - vlen(s);
  return pad > 0 ? s + " ".repeat(pad) : s;
}

/* ---- heat cells + sparklines --------------------------------------- */
export function heatCell(v, ramp) {
  if (v < 0) return bg(SILENT_BG) + " " + RESET;
  const r = ramp || HEAT_TX;
  return bg(r[Math.min(r.length - 1, Math.floor(v * r.length))]) + " " + RESET;
}
export function sparkline(hist, w, color = C_TX) {
  if (w <= 0 || hist.length === 0) return " ".repeat(Math.max(0, w));
  const vis = Math.min(w, hist.length);
  const start = hist.length - vis;
  let max = 0;
  for (let i = start; i < hist.length; i++) if (hist[i] > max) max = hist[i];
  let out = "";
  for (let i = 0; i < w - vis; i++) out += " ";
  if (max === 0) {
    for (let i = 0; i < vis; i++) out += fg(C_AXIS) + EIGHTH[0] + RESET;
  } else {
    for (let i = 0; i < vis; i++) {
      const v = hist[start + i] / max;
      const idx = Math.max(1, Math.min(8, Math.round(v * 8)));
      out += fg(color) + EIGHTH[idx] + RESET;
    }
  }
  return out;
}

/* ---- horizontal bar (used for per-destination bandwidth) ----------
 * Renders a single bar of width `w` showing `val/max` of bandwidth.
 * Uses block-fill with EIGHTH precision for sub-cell resolution. */
export function hbar(val, max, w, color) {
  if (w <= 0) return "";
  if (max <= 0 || val <= 0) return fg(C_AXIS) + "▱".repeat(w) + RESET;
  const filled = Math.min(w, Math.floor((val / max) * w));
  const frac = ((val / max) * w) - filled;
  let out = fg(color) + "▰".repeat(filled);
  if (filled < w) {
    const sub = Math.round(frac * 8);
    if (sub > 0) out += EIGHTH[Math.min(8, sub)];
    else out += "▱";
    out += "▱".repeat(Math.max(0, w - filled - 1));
  }
  return out + RESET;
}

/* ---- braille canvas (kept for parity with siblings) ---------------- */
const BRAILLE_DOT = [[0x01, 0x08], [0x02, 0x10], [0x04, 0x20], [0x40, 0x80]];
export function brailleCanvas(cw, ch) {
  const PW = cw * 2, PH = ch * 4;
  const mask = new Int32Array(cw * ch);
  const color = new Array(cw * ch).fill(0);
  return {
    PW, PH,
    set(px, py, col) {
      if (px < 0 || px >= PW || py < 0 || py >= PH) return;
      const i = (py >> 2) * cw + (px >> 1);
      mask[i] |= BRAILLE_DOT[py & 3][px & 1];
      if (col) color[i] = col;
    },
    rows() {
      const out = [];
      for (let cy = 0; cy < ch; cy++) {
        let line = "";
        for (let cx = 0; cx < cw; cx++) {
          const i = cy * cw + cx, m = mask[i];
          line += m === 0 ? " " : fg(color[i] || C_TX) + String.fromCodePoint(0x2800 + m) + RESET;
        }
        out.push(line);
      }
      return out;
    },
  };
}
