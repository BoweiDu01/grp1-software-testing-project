// fuzzer_hook.js
const MAP_SIZE = 65536;
const coverage_map = new Uint8Array(MAP_SIZE);
let prev_location = 0;

// 1. Attempt to find the target function
let targetAddr = null;
try {
    targetAddr = Module.findExportByName(null, "parse_ipv4") || 
                 DebugSymbol.fromName("parse_ipv4").address;
} catch (e) {
    // If not found, we are likely in the Parent/Bootloader process
}

// 2. The "Chef" Logic (Only runs in the Child process)
if (targetAddr) {
    console.log("[+] Target found at: " + targetAddr + ". Initializing instrumentation...");

    Interceptor.attach(targetAddr, {
        onEnter: function (args) {
            Stalker.follow(Process.getCurrentThreadId(), {
                transform: function (iterator) {
                    let instruction = iterator.next();
                    while (instruction !== null) {
                        const startAddress = instruction.address;
                        
                        // AFL-style Edge Coverage logic
                        const location = (startAddress.toInt32() >> 4) ^ (startAddress.toInt32() << 8);
                        const index = (location ^ prev_location) % MAP_SIZE;

                        iterator.putCallout((context) => {
                            if (coverage_map[index] === 0) {
                                coverage_map[index] = 1;
                                send({ type: 'new_block', address: startAddress });
                            }
                        });

                        prev_location = location >> 1;
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

    // 3. The "Real" Fuzz Export
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
    // 4. The "Dummy" Logic (Runs in the Parent process)
    // We must export the function name so Python's rpc.exports doesn't throw an error,
    // but it won't actually do anything until the child process is active.
    rpc.exports = {
        fuzz: function (payload) {
            // Do nothing in the bootloader
            return;
        }
    };
}