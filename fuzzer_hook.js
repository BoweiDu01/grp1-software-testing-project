// --- 1. Global State & Coverage Map ---
const MAP_SIZE = 65536;
const coverage_map = new Uint8Array(MAP_SIZE);
const thread_prev_location = new Map(); // threadId -> last location hash

// Batching buffers to reduce IPC overhead
let pendingEdges = [];
let pendingCmps = [];
let flushScheduled = false;

function scheduledFlush() {
    flushScheduled = false;
    if (pendingEdges.length > 0) send({ type: 'batch_edges', edges: pendingEdges.splice(0) });
    if (pendingCmps.length > 0) send({ type: 'batch_cmps', entries: pendingCmps.splice(0) });
}

function scheduleFlush() {
    if (!flushScheduled) {
        flushScheduled = true;
        setTimeout(scheduledFlush, 50);
    }
}

// --- 2. Target Discovery ---
let targetAddr = null;
try {
    // Attempt to find the target (add your hardcoded offset here if symbols are stripped)
    targetAddr = Module.findExportByName(null, "parse_ipv4") || 
                 DebugSymbol.fromName("parse_ipv4").address;
} catch (e) {}

// --- 3. The "Chef" Logic (Child Process) ---
if (targetAddr) {
    console.log("[+] Target found at: " + targetAddr + ". Merged instrumentation active.");

    Interceptor.attach(targetAddr, {
        onEnter: function (args) {
            const tid = Process.getCurrentThreadId();
            Stalker.follow(tid, {
                transform: function (iterator) {
                    let instruction = iterator.next();
                    if (instruction === null) return;

                    const blockAddr = instruction.address;
                    
                    // --- AFL-style Edge Coverage ---
                    // Generate a hash for this block
                    const location = (blockAddr.toInt32() >> 4) ^ (blockAddr.toInt32() << 8);
                    
                    iterator.putCallout((context) => {
                        const currentTid = Process.getCurrentThreadId();
                        const prevLoc = thread_prev_location.get(currentTid) || 0;
                        const index = (location ^ prevLoc) % MAP_SIZE;

                        if (coverage_map[index] === 0) {
                            coverage_map[index] = 1;
                            pendingEdges.push(blockAddr.toString());
                            scheduleFlush();
                        }
                        // Update per-thread previous location
                        thread_prev_location.set(currentTid, location >> 1);
                    });

                    // --- Instruction Walking (CMP Tracking) ---
                    while (instruction !== null) {
                        if (instruction.mnemonic === 'cmp') {
                            const instrAddr = instruction.address.toString();
                            iterator.putCallout((context) => {
                                try {
                                    // Tracking RAX/RBX distance (Adjust registers for macOS/ARM if needed)
                                    let val1 = context.rax.toInt32();
                                    let val2 = context.rbx.toInt32();
                                    pendingCmps.push({ 
                                        address: instrAddr, 
                                        distance: Math.abs(val1 - val2) 
                                    });
                                    scheduleFlush();
                                } catch (e) {}
                            });
                        }
                        iterator.keep();
                        instruction = iterator.next();
                    }
                }
            });
        },
        onLeave: function (retval) {
            Stalker.unfollow(Process.getCurrentThreadId());
            Stalker.flush();
        }
    });

    rpc.exports = {
        fuzz: function (payload) {
            const native_func = new NativeFunction(targetAddr, 'void', ['pointer', 'int']);
            const buffer = Memory.alloc(payload.length);
            buffer.writeByteArray(payload);
            try {
                native_func(buffer, payload.length);
            } catch (e) {
                send({ type: 'crash', error: e.message });
            }
        }
    };
} else {
    // --- 4. Dummy Logic (Parent Process) ---
    rpc.exports = {
        fuzz: function (payload) { return; }
    };
}