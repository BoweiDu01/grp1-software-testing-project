// fuzzer_hook.js
const MAP_SIZE = 65536;
const coverage_map = new Uint8Array(MAP_SIZE);
let prev_location = 0;
let pending_hits = []; // Buffer for new blocks

console.log("[*] Stalker active. Tracking basic blocks...");

Stalker.follow(Process.getCurrentThreadId(), {
    events: { compile: true },
    transform: function (iterator) {
        let instruction = iterator.next();
        while (instruction !== null) {
            const startAddress = instruction.address;
            const location = (startAddress.toInt32() >> 4) ^ (startAddress.toInt32() << 8);
            const index = (location ^ prev_location) % MAP_SIZE;

            iterator.putCallout((context) => {
                // Only push to the buffer if it's a completely new block
                if (coverage_map[index] === 0) {
                    coverage_map[index] = 1;
                    pending_hits.push(index);
                }
            });

            prev_location = location >> 1;
            iterator.keep();
            instruction = iterator.next();
        }
    }
});

// Flush the buffer to Python every 50 milliseconds
setInterval(function() {
    if (pending_hits.length > 0) {
        send({ type: "coverage_update", hits: pending_hits });
        pending_hits = []; // Clear the buffer after sending
    }
}, 50);