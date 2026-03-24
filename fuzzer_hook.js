// fuzzer_hook.js
const seen_edges = new Set();
const prevBlock = new Map(); // threadId -> last block address string (per-thread)

// Batch outgoing messages to reduce IPC round-trips with Python
const pendingEdges = [];
const pendingCmps = [];
let flushScheduled = false;

function scheduledFlush() {
    flushScheduled = false;
    if (pendingEdges.length > 0)
        send({ type: 'batch_edges', edges: pendingEdges.splice(0) });
    if (pendingCmps.length > 0)
        send({ type: 'batch_cmps', entries: pendingCmps.splice(0) });
}

function scheduleFlush() {
    if (!flushScheduled) {
        flushScheduled = true;
        setTimeout(scheduledFlush, 50);
    }
}

Stalker.follow({
    transform: function (iterator) {
        let instruction = iterator.next();
        if (instruction === null) return;

        // Capture block start address at compile time
        const blockAddr = instruction.address.toString();

        // Insert edge-tracking callout at block entry (runs once per execution of this block)
        iterator.putCallout((context) => {
            const tid = Process.getCurrentThreadId().toString();
            const prev = prevBlock.get(tid) || '0';
            const edge = prev + '->' + blockAddr;
            if (!seen_edges.has(edge)) {
                seen_edges.add(edge);
                pendingEdges.push(edge);
                scheduleFlush();
            }
            prevBlock.set(tid, blockAddr);
        });
        iterator.keep();

        // Walk remaining instructions in the block, instrumenting CMP operands
        instruction = iterator.next();
        while (instruction !== null) {
            if (instruction.mnemonic === 'cmp') {
                const instrAddr = instruction.address.toString();
                iterator.putCallout((context) => {
                    try {
                        let val1 = context.rax.toInt32();
                        let val2 = context.rbx.toInt32();
                        pendingCmps.push({ address: instrAddr, distance: Math.abs(val1 - val2) });
                        scheduleFlush();
                    } catch (e) {}
                });
            }
            iterator.keep();
            instruction = iterator.next();
        }
    }
});
