/* bytetop — main entry point.
 *
 * One ringbuf in, three event kinds out (OPEN / BYTES / CLOSE).
 * state.js owns the model; dashboard.js owns the pixels. Every byte
 * on the wire that this dashboard accounts for came from a kernel
 * tracepoint — no /proc parsing, no graph queries, no decryption. */

import { RingBuf } from "yeet:bpf";
import bpf from "./bin/bytetop.bpf.o";

import { onEvent, advance, TICK_MS } from "./state.js";
import { renderDashboard, clearScreen } from "./dashboard.js";

const HIDE = "\x1b[?25l";
const SHOW = "\x1b[?25h";

const tty = globalThis.tty;
if (!tty) {
  console.error("bytetop: no tty available (yeet didn't expose globalThis.tty)");
  throw new Error("missing tty");
}

let cols = 100, rows = 36;
function readSize() {
  const sz = tty.size?.();
  if (sz) { cols = sz.cols ?? cols; rows = sz.rows ?? rows; }
}
readSize();
tty.on?.("resize", () => { readSize(); paint(); });

function paint() {
  const frame = renderDashboard(cols, rows);
  if (tty.beginFrame) {
    tty.beginFrame();
    tty.write(frame);
    tty.endFrame();
  } else {
    tty.write(frame);
  }
}

async function main() {
  tty.write(HIDE);
  tty.write(clearScreen());

  /* Bind the BPF ringbuf and stream byte-accounting events into state.
   * yeet wraps the decoded record under the struct name, but some
   * builds hand the record directly — accept either. */
  const control = await bpf
    .bind("events", { kind: "ringbuf", btf_struct: "conn_evt" })
    .start();

  await new RingBuf(control, "events").subscribe(
    (evt) => onEvent(evt.conn_evt ?? evt),
    (err) => console.error("bytetop ringbuf error:", err?.message ?? err),
  );

  /* render cadence */
  setInterval(() => { advance(); paint(); }, TICK_MS);

  /* first frame so the screen isn't blank until the first tick */
  paint();
}

main().catch((e) => {
  tty.write(SHOW);
  console.error(e?.stack ?? e?.message ?? e);
});
