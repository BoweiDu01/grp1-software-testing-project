// fuzzer_hook.js
const seen_edges = new Set();
const prevBlock = new Map(); // tid -> last block
const cmp_best_distances = {};

let run_path_blocks = {};
let run_block_hits = {};

const pendingEdges = [];
const pendingCmps = [];
let flushScheduled = false;

function scheduledFlush() {
  flushScheduled = false;
  if (pendingEdges.length > 0) {
    send({ type: "batch_edges", edges: pendingEdges.splice(0) });
  }
  if (pendingCmps.length > 0) {
    send({ type: "batch_cmps", entries: pendingCmps.splice(0) });
  }
}

function scheduleFlush() {
  if (!flushScheduled) {
    flushScheduled = true;
    setTimeout(scheduledFlush, 50);
  }
}

function parseImmediateValue(token) {
  if (!token) return null;
  const clean = token.trim().toLowerCase();
  if (clean.startsWith("0x")) {
    const v = parseInt(clean, 16);
    return Number.isNaN(v) ? null : v;
  }
  if (/^-?\d+$/.test(clean)) {
    const v = parseInt(clean, 10);
    return Number.isNaN(v) ? null : v;
  }
  return null;
}

function readRegisterValue(context, name) {
  try {
    if (!name) return null;
    const key = name.trim().toLowerCase();
    if (context[key] === undefined || context[key] === null) return null;
    return ptr(context[key]).toInt32();
  } catch (_) {
    return null;
  }
}

function maybeQueueCmpDistance(instruction, context) {
  try {
    const mnem = (instruction.mnemonic || "").toLowerCase();
    if (!(mnem === "cmp" || mnem === "sub" || mnem === "test")) return;

    const opStr = instruction.opStr || "";
    const parts = opStr.split(",");
    if (parts.length !== 2) return;

    const lhs = parts[0].trim();
    const rhs = parts[1].trim();

    let regVal = readRegisterValue(context, lhs);
    let immVal = parseImmediateValue(rhs);

    if (regVal === null || immVal === null) {
      regVal = readRegisterValue(context, rhs);
      immVal = parseImmediateValue(lhs);
    }

    if (regVal === null || immVal === null) return;
    const dist = Math.abs(regVal - immVal);
    const addr = instruction.address.toString();

    if (
      cmp_best_distances[addr] === undefined ||
      dist < cmp_best_distances[addr]
    ) {
      cmp_best_distances[addr] = dist;
      pendingCmps.push({ address: addr, distance: dist });
      scheduleFlush();
    }
  } catch (_) {
    // Ignore unsupported operand forms.
  }
}

function tryResolveTarget(name) {
  let addr = null;

  try {
    addr = Module.findExportByName(null, name);
    if (addr) return addr;
  } catch (_) {}

  try {
    const sym = DebugSymbol.fromName(name);
    if (sym && sym.address && !sym.address.isNull()) return sym.address;
  } catch (_) {}

  try {
    const modules = Process.enumerateModules();
    for (let i = 0; i < modules.length; i++) {
      const m = modules[i];
      try {
        const exps = Module.enumerateExportsSync(m.name);
        for (let j = 0; j < exps.length; j++) {
          const e = exps[j];
          if (
            e.type === "function" &&
            e.name.toLowerCase().indexOf(name.toLowerCase()) !== -1
          ) {
            return e.address;
          }
        }
      } catch (_) {}
    }
  } catch (_) {}

  return null;
}

const targetAddr = tryResolveTarget("parse_ipv4");
if (targetAddr) {
  send({ type: "hook_status", status: "ok", target: targetAddr.toString() });
} else {
  send({ type: "hook_status", status: "missing_target", target: null });
}

function runStalkerAndInvoke(native_func, buffer, length) {
  const tid = Process.getCurrentThreadId();
  run_path_blocks = {};
  run_block_hits = {};

  Stalker.follow(tid, {
    transform: function (iterator) {
      let instruction = iterator.next();
      while (instruction !== null) {
        const blockAddr = instruction.address.toString();

        iterator.putCallout((context) => {
          const tidKey = Process.getCurrentThreadId().toString();
          const prev = prevBlock.get(tidKey) || "0";
          const edge = prev + "->" + blockAddr;

          if (!seen_edges.has(edge)) {
            seen_edges.add(edge);
            pendingEdges.push(edge);
            scheduleFlush();
          }
          prevBlock.set(tidKey, blockAddr);

          run_path_blocks[blockAddr] = 1;
          run_block_hits[blockAddr] = (run_block_hits[blockAddr] || 0) + 1;
          maybeQueueCmpDistance(instruction, context);
        });

        iterator.keep();
        instruction = iterator.next();
      }
    },
  });

  try {
    native_func(buffer, length);
  } finally {
    Stalker.unfollow(tid);
    Stalker.flush();

    const blockKeys = Object.keys(run_path_blocks).sort();
    let maxLoopIterations = 0;
    for (const key in run_block_hits) {
      if (Object.prototype.hasOwnProperty.call(run_block_hits, key)) {
        if (run_block_hits[key] > maxLoopIterations) {
          maxLoopIterations = run_block_hits[key];
        }
      }
    }

    send({
      type: "run_metrics",
      path_depth: blockKeys.length,
      max_loop_iterations: maxLoopIterations,
      top_blocks: blockKeys.slice(0, 16),
    });
    scheduledFlush();
  }
}

rpc.exports = {
  fuzz: function (payload) {
    if (!targetAddr) {
      return;
    }

    const native_func = new NativeFunction(targetAddr, "void", [
      "pointer",
      "int",
    ]);
    const buffer = Memory.alloc(payload.length);
    buffer.writeByteArray(payload);

    try {
      runStalkerAndInvoke(native_func, buffer, payload.length);
    } catch (e) {
      send({ type: "crash", error: e.message });
      send({ type: "output", text: e.message });
      scheduledFlush();
    }
  },
};
