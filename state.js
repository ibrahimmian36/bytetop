/* Application state + event ingest for bytetop.
 *
 * BPF emits three event kinds on one ringbuf:
 *   kind 0  OPEN   new connection observed
 *   kind 1  BYTES  periodic byte delta on a tracked connection
 *   kind 2  CLOSE  connection terminating
 *
 * The model below maintains:
 *   • a Map<sk, ConnInfo> of currently-tracked connections
 *   • per-process aggregators (cumulative tx/rx, distinct dests, conns)
 *   • per-destination aggregators (cumulative tx/rx, contributing procs)
 *   • per-tick deltas rolled into history arrays for sparklines
 *   • a recent-events feed for the live panel */

import { portClass } from "./render.js";

export const TICK_MS    = 200;
export const WINDOW_MS  = 10_000;       /* rolling window for "top" tables */
export const HIST_LEN   = 240;          /* ~48 s of history at 200 ms ticks */
const   CLOSE_FADE_MS   = 5_000;
const   PROC_STALE_MS   = 60_000;
const   DEST_STALE_MS   = 60_000;
const   FEED_KEEP       = 200;

/* ---- global counters + history ------------------------------------- */
export const startTime = Date.now();
export const tot = {
  events: 0,
  opens: 0,
  closes: 0,
  bytes_tx: 0,        /* cumulative across all conns ever */
  bytes_rx: 0,
  bytes_tx_enc: 0,    /* split by encrypted-port classification */
  bytes_tx_plain: 0,
  bytes_rx_enc: 0,
  bytes_rx_plain: 0,
};

/* per-tick deltas, rolled into history each advance() */
let tickTx = 0, tickRx = 0;
let tickTxEnc = 0, tickRxEnc = 0;
let tickOpens = 0;
export const txHist    = [];   /* total bytes tx per tick */
export const rxHist    = [];
export const txEncHist = [];   /* encrypted share */
export const rxEncHist = [];
export const opensHist = [];   /* new conns per tick */
export const activeHist = [];  /* currently-active conn count per tick */
function pushHist(arr, v) { arr.push(v); if (arr.length > HIST_LEN) arr.shift(); }

/* ---- anonymize ----------------------------------------------------- */
const anon = !!globalThis.yeet?.args?.anonymize;
const aliasMaps = { name: new Map(), addr: new Map() };
function aliasGen(kind, key, prefix) {
  const m = aliasMaps[kind];
  let a = m.get(key);
  if (!a) { a = prefix + String(m.size + 1).padStart(2, "0"); m.set(key, a); }
  return a;
}
export function aName(s) { return anon && s ? aliasGen("name", s, "proc-") : s; }
export function aAddr(s) { return anon && s ? aliasGen("addr", s, "host-") : s; }

/* ---- connection table ---------------------------------------------- */
/* key: sock pointer as hex string (handles bigint identity safely) */
const conns = new Map();

/* ---- aggregators --------------------------------------------------- */
const procStats = new Map();   /* "pid:comm" → ProcStat */
const destStats = new Map();   /* "family:addr:port" → DestStat */

function getProc(pid, comm) {
  const key = pid + ":" + comm;
  let p = procStats.get(key);
  if (!p) {
    p = {
      pid, comm,
      bytes_tx: 0, bytes_rx: 0,
      tx_rate_hist: [], rx_rate_hist: [],
      conn_count: 0,
      dests: new Set(),
      last_seen: 0,
    };
    procStats.set(key, p);
  }
  return p;
}
function getDest(family, addrBytes, port) {
  /* key string deterministically encodes (family, raw addr, port) */
  let key = String(family) + ":";
  for (let i = 0; i < 16; i++) key += addrBytes[i].toString(16).padStart(2, "0");
  key += ":" + port;
  let d = destStats.get(key);
  if (!d) {
    const cp = new Uint8Array(16);
    for (let i = 0; i < 16; i++) cp[i] = addrBytes[i] | 0;
    d = {
      family, addr: cp, port,
      cls: portClass(port),
      bytes_tx: 0, bytes_rx: 0,
      tx_rate_hist: [], rx_rate_hist: [],
      conn_count: 0,
      procs: new Set(),
      last_seen: 0,
    };
    destStats.set(key, d);
  }
  return d;
}

/* ---- recent events feed -------------------------------------------- */
const feed = [];
function pushFeed(rec) { feed.push(rec); if (feed.length > FEED_KEEP) feed.shift(); }

/* ---- decoders ------------------------------------------------------ */
function num(v) { return typeof v === "bigint" ? Number(v) : v; }
function bigKey(v) { return typeof v === "bigint" ? v.toString(16) : String(v); }
function bytesAsArray(b) {
  const out = new Uint8Array(16);
  if (!b) return out;
  for (let i = 0; i < 16; i++) out[i] = b[i] | 0;
  return out;
}

/* ---- ingest -------------------------------------------------------- */
export function onEvent(e) {
  if (!e) return;
  tot.events++;
  const kind = num(e.kind) | 0;
  const now = Date.now();
  const sk = bigKey(e.sk);
  const family = num(e.family) | 0;
  const sport  = num(e.sport) & 0xffff;
  const dport  = num(e.dport) & 0xffff;
  const pid    = num(e.pid) | 0;
  const comm   = String(e.comm || "?");
  const saddr  = bytesAsArray(e.saddr);
  const daddr  = bytesAsArray(e.daddr);
  const bytes_tx = num(e.bytes_tx) || 0;
  const bytes_rx = num(e.bytes_rx) || 0;
  const delta_tx = num(e.delta_tx) || 0;
  const delta_rx = num(e.delta_rx) || 0;

  if (kind === 0) {
    /* OPEN: create connection record */
    tot.opens++; tickOpens++;
    let c = conns.get(sk);
    if (!c) {
      c = {
        sk, family, saddr, sport, daddr, dport,
        pid, comm,
        bytes_tx: 0, bytes_rx: 0,
        first_seen: now, last_active: now, closed: 0,
        cls: portClass(dport),
      };
      conns.set(sk, c);
    } else {
      /* Repeat OPEN for the same sk — could happen if the BPF state
       * was reset between OPENs, or if a sock pointer was reused after
       * a CLOSE event was missed. Accept the new pid/comm as the
       * authoritative attribution but keep the conn's byte counters,
       * so we don't drop in-flight accounting on the floor. */
      c.pid = pid; c.comm = comm; c.last_active = now;
    }
    /* prime per-proc / per-dest with the conn */
    const p = getProc(c.pid, c.comm);
    p.conn_count++; p.last_seen = now;
    p.dests.add(family + ":" + dport + ":" +
                Array.from(daddr).map(b => b.toString(16)).join(""));
    const d = getDest(c.family, c.daddr, c.dport);
    d.conn_count++; d.last_seen = now;
    d.procs.add(c.pid + ":" + c.comm);

    pushFeed({
      ts: now, kind: "open", sk,
      family: c.family,
      saddr: c.saddr, sport: c.sport,
      daddr: c.daddr, dport: c.dport,
      pid: c.pid, comm: c.comm,
      cls: c.cls,
    });
    return;
  }

  if (kind === 1) {
    /* BYTES: apply delta */
    let c = conns.get(sk);
    if (!c) {
      /* missed OPEN — create a stub so the bytes don't get lost */
      c = {
        sk, family, saddr, sport, daddr, dport,
        pid, comm,
        bytes_tx: 0, bytes_rx: 0,
        first_seen: now, last_active: now, closed: 0,
        cls: portClass(dport),
      };
      conns.set(sk, c);
    }
    /* trust delta_tx / delta_rx for incrementing — bytes_tx/rx in the
     * event are the kernel-side cumulative which may be ahead of what
     * we've accounted for. */
    c.bytes_tx += delta_tx;
    c.bytes_rx += delta_rx;
    c.last_active = now;

    tickTx += delta_tx;
    tickRx += delta_rx;
    tot.bytes_tx += delta_tx;
    tot.bytes_rx += delta_rx;
    if (c.cls === "enc") {
      tickTxEnc += delta_tx; tickRxEnc += delta_rx;
      tot.bytes_tx_enc += delta_tx; tot.bytes_rx_enc += delta_rx;
    } else if (c.cls === "plain") {
      tot.bytes_tx_plain += delta_tx; tot.bytes_rx_plain += delta_rx;
    }

    /* roll into proc + dest aggregators */
    const p = getProc(c.pid, c.comm);
    p.bytes_tx += delta_tx; p.bytes_rx += delta_rx; p.last_seen = now;

    const d = getDest(c.family, c.daddr, c.dport);
    d.bytes_tx += delta_tx; d.bytes_rx += delta_rx; d.last_seen = now;
    return;
  }

  if (kind === 2) {
    /* CLOSE: finalize, schedule fade */
    tot.closes++;
    let c = conns.get(sk);
    if (c) {
      /* there can be a final byte-delta in this event we haven't seen */
      const extraTx = Math.max(0, bytes_tx - c.bytes_tx);
      const extraRx = Math.max(0, bytes_rx - c.bytes_rx);
      if (extraTx + extraRx > 0) {
        c.bytes_tx += extraTx; c.bytes_rx += extraRx;
        tickTx += extraTx; tickRx += extraRx;
        tot.bytes_tx += extraTx; tot.bytes_rx += extraRx;
        if (c.cls === "enc") {
          tickTxEnc += extraTx; tickRxEnc += extraRx;
          tot.bytes_tx_enc += extraTx; tot.bytes_rx_enc += extraRx;
        } else if (c.cls === "plain") {
          tot.bytes_tx_plain += extraTx; tot.bytes_rx_plain += extraRx;
        }
        const p = getProc(c.pid, c.comm);
        p.bytes_tx += extraTx; p.bytes_rx += extraRx; p.last_seen = now;
        const d = getDest(c.family, c.daddr, c.dport);
        d.bytes_tx += extraTx; d.bytes_rx += extraRx; d.last_seen = now;
      }
      c.closed = now;
      pushFeed({
        ts: now, kind: "close", sk,
        family: c.family,
        saddr: c.saddr, sport: c.sport,
        daddr: c.daddr, dport: c.dport,
        pid: c.pid, comm: c.comm,
        bytes_tx: c.bytes_tx, bytes_rx: c.bytes_rx,
        cls: c.cls,
        duration_ms: now - c.first_seen,
      });
    }
    return;
  }
}

/* ---- per-tick roll + reaping --------------------------------------- */
export function advance() {
  const now = Date.now();

  /* roll deltas into history */
  pushHist(txHist, tickTx);    tickTx = 0;
  pushHist(rxHist, tickRx);    tickRx = 0;
  pushHist(txEncHist, tickTxEnc); tickTxEnc = 0;
  pushHist(rxEncHist, tickRxEnc); tickRxEnc = 0;
  pushHist(opensHist, tickOpens); tickOpens = 0;

  /* count active conns */
  let active = 0;
  for (const c of conns.values()) if (!c.closed) active++;
  pushHist(activeHist, active);

  /* roll per-proc and per-dest tx/rx into their own per-tick rate
   * histories. We sample the cumulative bytes at each tick and
   * compute deltas in a closure-capture pattern. Cheap and correct. */
  /* Use a sentinel key to stash last-known totals on the object. */
  for (const p of procStats.values()) {
    const lastTx = p._lastTx ?? p.bytes_tx;
    const lastRx = p._lastRx ?? p.bytes_rx;
    pushHist(p.tx_rate_hist, p.bytes_tx - lastTx);
    pushHist(p.rx_rate_hist, p.bytes_rx - lastRx);
    p._lastTx = p.bytes_tx; p._lastRx = p.bytes_rx;
  }
  for (const d of destStats.values()) {
    const lastTx = d._lastTx ?? d.bytes_tx;
    const lastRx = d._lastRx ?? d.bytes_rx;
    pushHist(d.tx_rate_hist, d.bytes_tx - lastTx);
    pushHist(d.rx_rate_hist, d.bytes_rx - lastRx);
    d._lastTx = d.bytes_tx; d._lastRx = d.bytes_rx;
  }

  /* reap: closed conns past fade window */
  for (const [sk, c] of conns) {
    if (c.closed && now - c.closed > CLOSE_FADE_MS) conns.delete(sk);
  }
  /* reap stale aggregators */
  for (const [k, p] of procStats) if (now - p.last_seen > PROC_STALE_MS) procStats.delete(k);
  for (const [k, d] of destStats) if (now - d.last_seen > DEST_STALE_MS) destStats.delete(k);

  /* feed pruning: drop entries that aged out of the 60 s display window */
  while (feed.length && now - feed[0].ts > 60_000) feed.shift();
}

/* ---- accessors ----------------------------------------------------- */
const oneSecTicks = Math.max(1, Math.round(1000 / TICK_MS));
function sumTail(arr, n) {
  const start = Math.max(0, arr.length - n);
  let s = 0;
  for (let i = start; i < arr.length; i++) s += arr[i];
  return s;
}

export function liveRates() {
  return {
    tx_bps: sumTail(txHist, oneSecTicks),
    rx_bps: sumTail(rxHist, oneSecTicks),
    tx_enc_bps: sumTail(txEncHist, oneSecTicks),
    rx_enc_bps: sumTail(rxEncHist, oneSecTicks),
    active: activeHist.length ? activeHist[activeHist.length - 1] : 0,
  };
}

/* Top processes by current bandwidth (tx+rx in the last second). */
export function topProcs(n) {
  const list = [];
  for (const p of procStats.values()) {
    const tx = sumTail(p.tx_rate_hist, oneSecTicks);
    const rx = sumTail(p.rx_rate_hist, oneSecTicks);
    list.push({ p, tx_bps: tx, rx_bps: rx, total: tx + rx });
  }
  list.sort((a, b) => b.total - a.total);
  return list.slice(0, n);
}

/* Top destinations by current bandwidth. */
export function topDests(n) {
  const list = [];
  for (const d of destStats.values()) {
    const tx = sumTail(d.tx_rate_hist, oneSecTicks);
    const rx = sumTail(d.rx_rate_hist, oneSecTicks);
    list.push({ d, tx_bps: tx, rx_bps: rx, total: tx + rx });
  }
  list.sort((a, b) => b.total - a.total);
  return list.slice(0, n);
}

export function recentEvents(n) { return feed.slice(-n).reverse(); }
