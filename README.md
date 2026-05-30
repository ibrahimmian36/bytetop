# bytetop

**iotop for the wire** — a live, per-process, per-destination TCP traffic dashboard.

TLS means `tcpdump` can't read the bytes. But the kernel still knows **who** is talking to **where**, and **how much**. `bytetop` surfaces all of that in real time, without decrypting anything.

It's built on [**yeet**](https://yeet.cx), a runtime that makes a kernel-side BPF program, a per-tick render loop, and a JS state model feel like one program.

<p align="center">
  <img src="assets/bytetop.gif" alt="bytetop demo" width="820">
</p>

---

## What you actually see

A header strip with live system rates and the share of bandwidth flowing on **encrypted** ports.

A **TRAFFIC BY DESTINATION** panel — every remote endpoint visible to the kernel right now, sorted by current bandwidth, with two color-coded marks:

- `●` green — port that overwhelmingly carries an encrypted protocol (`443`, `22`, `8443`, `993`, `5223`, `51820`, …)
- `○` yellow — port still widely used in cleartext (`80`, `53`, `3306`, `5432`, `6379`, …)
- `·` neutral — unknown / ephemeral, no claim made

Each row shows the endpoint, transmit and receive rates in B/s, dual horizontal bars, the live connection count, and a transmit-rate sparkline over the last few seconds.

A **TOTAL BANDWIDTH** strip — system-wide tx and rx painted as a heatmap over the last ~48 s. Tx fades cyan from top down; rx fades orange from bottom up. The peak under the top label is the global scale across both directions, so the two halves are visually comparable.

A **TOP PROCESSES** table — current bandwidth per `(pid, comm)`, plus a count of distinct destinations each process is talking to. A web browser will glow with dozens of destinations; a backup job will glow with one.

A **CONNECTION FEED** — `●` opens and `✕` closes in chronological order, with the local and remote endpoints, the process, and (for closes) the total tx/rx for the connection's lifetime.

```
 ▌ BYTETOP · per-process per-destination traffic observatory ────────────────────────────────────────────────
  ● LIVE 00:42   38 active   ▲ 4.2MB/s ▼ 12MB/s   97% enc   18/s open

  TRAFFIC BY DESTINATION · ● enc  ○ plain  · other ──────────────────────────────────────────────────────────
  ● 140.82.121.4:443           ▲ 1.8MB/s   ▼ 4.1MB/s  ▰▰▰▰▰▱▱ ▰▰▰▰▰▰▰▱   12 conn  ▂▃▆▇█▆▅▄▃▄▆▇█▇▆▅▃▂▃▅▆▇
  ● 104.16.28.35:443           ▲ 980KB/s   ▼ 2.4MB/s  ▰▰▰▱▱▱▱ ▰▰▰▰▰▱▱▱    8 conn  ▁▂▄▅▆▆▅▄▃▃▄▅▆▅▄▃▂▁▂▃▄▅
  ● [2001:4860:4860::8888]:443 ▲ 410KB/s   ▼ 1.1MB/s  ▰▱▱▱▱▱▱ ▰▰▰▱▱▱▱▱    3 conn  ▁▁▂▃▄▄▃▂▁▁▂▃▄▃▂▁▁▁▂▂▃▄
  ● 1.1.1.1:443                ▲ 120KB/s   ▼ 380KB/s  ▰▱▱▱▱▱▱ ▰▱▱▱▱▱▱▱    4 conn  ▁▁▂▂▃▃▂▁▁▁▂▃▃▂▁▁▁▁▂▂▂▃
  ○ 10.0.0.50:5432             ▲ 240KB/s   ▼ 95KB/s   ▰▱▱▱▱▱▱ ▱▱▱▱▱▱▱▱    2 conn  ▂▃▅▄▃▂▂▃▄▃▂▁▂▃▄▅▃▂▂▃▄▃
  ● 22.0.0.5:22                ▲ 50KB/s    ▼ 8KB/s    ▱▱▱▱▱▱▱ ▱▱▱▱▱▱▱▱    1 conn  ▁▁▁▂▂▁▁▁▂▂▁▁▁▁▁▂▂▁▁▁▁▁
  ○ 10.0.0.51:6379             ▲ 12KB/s    ▼ 24KB/s   ▱▱▱▱▱▱▱ ▱▱▱▱▱▱▱▱    5 conn  ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁

  TOTAL BANDWIDTH · 240MB ▲ sent · 1.2GB ▼ received cumulative ────────────────────────────────────────────────
  ▲ tx 5MB/s │ ░░░░░░░░░░░░░░░░░▒▒▒▓▓██████▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓██▓▓▒▒▒░░░░░░
             │ ░░░░░▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░
             │ ░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
             │ ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
  ▼ rx 12MB/s│ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

  TOP PROCESSES · 10s window ──────────────────────────────────────────────────────────────────────────────────
  chrome           pid 1834  2.1MB/s   5.8MB/s   23 dest
  firefox          pid 2241  580KB/s   1.4MB/s   12 dest
  curl             pid 9911  240KB/s   95KB/s     1 dest
  node             pid 3344  120KB/s   380KB/s    4 dest
  ssh              pid 6712  50KB/s    8KB/s      1 dest

  CONNECTION FEED · opens and closes, newest first ────────────────────────────────────────────────────────────
   00:42  ● ● OPEN  10.0.0.12:51932          → 140.82.121.4:443     pid 1834 chrome
   00:42  ○ ● OPEN  10.0.0.12:51931          → 10.0.0.51:6379       pid 3344 node
   00:42  ● ✕ CLOSE 10.0.0.12:48211          → 104.16.28.35:443     2.1MB/5.4MB  pid 1834 chrome
   00:42  ● ● OPEN  10.0.0.12:51930          → 1.1.1.1:443          pid 2241 firefox
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

## Quick start

```sh
curl -fsSL https://yeet.cx | sh
yeet run https://github.com/ibrahimmian36/bytetop
```

For a shareable screenshot, anonymize process names and remote addresses (everything identifying gets relabeled `proc-01`, `host-02`, …):

```sh
yeet run https://github.com/ibrahimmian36/bytetop -- --anonymize
```

Runs until `Ctrl-C`. Resize the terminal and the layout reflows; minimum 80×28.

## What's under the hood

Three BPF programs feed one ring buffer:

| BPF program        | hook                            | what it does                                                |
|--------------------|---------------------------------|-------------------------------------------------------------|
| `on_set_state`     | `tp_btf/inet_sock_set_state`    | track new conns at `TCP_ESTABLISHED`, reap at `TCP_CLOSE`   |
| `on_sendmsg`       | `fentry/tcp_sendmsg`            | count tx bytes; fix pid to the real sender (app ctx)        |
| `on_cleanup_rbuf`  | `fentry/tcp_cleanup_rbuf`       | count rx bytes; fix pid to the real receiver (app ctx)      |

One `HASH` map (`conns`, keyed by sock pointer) stores per-connection state and cumulative byte counts. One `RINGBUF` (256 KiB) carries three event kinds to JS:

- `OPEN` — new connection observed, after we know who owns it
- `BYTES` — periodic delta, emitted every 64 KiB transferred in either direction
- `CLOSE` — connection ending, with the final cumulative byte counts

That last design choice — emit-on-threshold rather than emit-per-send — naturally rate-limits chatty connections to roughly one event per 64 KiB per direction. A connection moving 100 Mb/s produces ~200 events/s; a connection that idles produces zero.

The dashboard runs in yeet's V8 runtime, subscribing to that ring buffer and rendering the terminal UI:

- `main.js` — entry: tty size, render loop, BPF bind/subscribe
- `state.js` — live data + per-tick history + per-proc / per-dest aggregators
- `render.js` — ANSI, color ramps, byte/port formatters, the encrypted-vs-plaintext palette (pure)
- `dashboard.js` — panels + layout (`renderDashboard`)

## Requirements

- Linux ≥ 5.5 (for `fentry` and `tp_btf`); modern distros are fine
- Kernel BTF: `CONFIG_DEBUG_INFO_BTF=y`, default on current Arch, Fedora, Ubuntu, and Debian 12+
- `CAP_BPF` + `CAP_PERFMON` (typically root)
- `clang` and `bpftool` to build the BPF object — `yeet run` does this for you on first launch

## Build it from a clone

```sh
git clone https://github.com/ibrahimmian36/bytetop
cd bytetop
make                    # builds bin/bytetop.bpf.o
sudo yeet main.js       # run from source
```

`make clean` removes `bin/`. `make distclean` also removes the generated `include/vmlinux.h`.

## Caveats

- **Process attribution is best-effort.** TCP state transitions can fire from softirq context (e.g. when a SYN-ACK arrives), where `current` is whatever happened to be scheduled — usually `swapper` or a `kworker`. We refuse those names and let the first `tcp_sendmsg` or `tcp_cleanup_rbuf` from the real app context update the connection's owner. For typical apps that send *or* receive anything at all, attribution converges within microseconds. The pathological case — a tracked connection whose user never reads received data and never sends — keeps whatever was current at `ESTABLISHED`.
- **Connections created before bytetop starts are invisible** until they next transition state. There's no kernel walk on startup — bytetop only sees connections it watched open.
- **The encrypted-port classification is a heuristic.** A port-based palette gets HTTPS, SSH, IMAPS, etc. right virtually always, but it's wrong for TLS on non-standard ports and for the occasional cleartext service on `443`. If you need a stronger encryption-posture claim, hook the TLS handshake itself — that's a different tool.
- **Ringbuf overflow drops events under extreme load.** The 256 KiB ringbuf can hold roughly 2 k threshold-emitted events at a time; sustained tens of thousands of byte-emissions per second can drop. Either raise the threshold (less precise rates) or raise the ringbuf size (higher memory).
- **UDP is not tracked.** This is a TCP-only observatory by design — the hooks chosen (`tcp_sendmsg`, `tcp_cleanup_rbuf`, `inet_sock_set_state`) all fire for TCP only.

## Differences from sibling tools

- **vs `httpsnoop`** — `httpsnoop` is a line-oriented CLI that dumps HTTP requests. `bytetop` is a dashboard that *doesn't* inspect content; it surfaces who/where/how-much for *every* TCP connection, encrypted or not.
- **vs `flowtop`** — `flowtop` focuses on TCP state transitions and retransmits; the signature visual is a per-state weather heatmap. `bytetop` focuses on *byte flows* — bandwidth per process and per destination.
- **vs `tcpdump`** — `tcpdump` reads packets; `bytetop` reads kernel-side accounting. `bytetop` knows which process owns each byte; `tcpdump` does not.

---

Built by [yeet](https://yeet.cx). yeet is a Linux runtime for writing eBPF programs and live system dashboards in JavaScript.
