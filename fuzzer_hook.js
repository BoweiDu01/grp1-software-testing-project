// fuzzer_hook.js
const seen_edges = new Set();
let prev_block = "0";

// DELETE OR COMMENT OUT ALL MODULE FILTERING LOGIC
// We want to see IF we can get any blocks at all.
function isMainModule(addr) {
    return true; 
}

Stalker.follow({
    events: { block: true },
    onReceive: function (events) {
        const blocks = Stalker.parse(events);
        blocks.forEach(b => {
            let currStr = b[0].toString();
            let edge = prev_block + "->" + currStr;
            if (!seen_edges.has(edge)) {
                seen_edges.add(edge);
                send({ type: 'new_block', address: currStr });
            }
            prev_block = currStr;
        });
    },
    transform: function (iterator) {
        let instruction = iterator.next();
        while (instruction !== null) {
            // Instrument ALL CMPs for now to verify logic
            if (instruction.mnemonic === 'cmp') {
                const instrAddr = instruction.address;
                iterator.putCallout((context) => {
                    try {
                        let val1 = context.rax.toInt32();
                        let val2 = context.rbx.toInt32();
                        send({ 
                            type: 'cmp_distance', 
                            address: instrAddr.toString(), 
                            distance: Math.abs(val1 - val2) 
                        });
                    } catch (e) {}
                });
            }
            iterator.keep();
            instruction = iterator.next();
        }
    }
});