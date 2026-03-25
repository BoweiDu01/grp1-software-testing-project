import os
import random
import numpy as np
import frida
import sys
import time
import hashlib
import psutil
import threading

def set_reproducibility(seed_value=7):
    random.seed(seed_value)
    np.random.seed(seed_value)
    print(f"[*] Fuzzing with Fixed Seed: {seed_value}")

# --- 1. Corpus Loader ---
class CorpusLoader:
    def __init__(self, corpus_dir):
        self.seeds = []
        if not os.path.exists(corpus_dir):
            os.makedirs(corpus_dir)
            with open(os.path.join(corpus_dir, "seed1.txt"), "wb") as f:
                f.write(b"192.168.1.1")
        for root, dirs, files in os.walk(corpus_dir):
            for file in files:
                path = os.path.join(root, file)
                with open(path, 'rb') as f:
                    self.seeds.append(f.read())
        print(f"Loaded {len(self.seeds)} seeds.")

    def get_random_seed(self):
        return random.choice(self.seeds)

# --- 2. Mutation Operators ---
def mut_bitflip(data):
    if not data: return data
    res = bytearray(data)
    idx = random.randint(0, len(res) - 1)
    res[idx] ^= (1 << random.randint(0, 7))
    return bytes(res)

def mut_arithmetic(data):
    if not data: return data
    res = bytearray(data)
    idx = random.randint(0, len(res) - 1)
    val = random.randint(-35, 35)
    res[idx] = (res[idx] + val) % 256
    return bytes(res)

def mut_interest(data):
    if not data: return data
    interesting = [0, 1, 127, 128, 255, 0xffff, 0xffffffff]
    res = bytearray(data)
    idx = random.randint(0, len(res) - 1)
    val = random.choice(interesting)
    res[idx] = val % 256 
    return bytes(res)

def mut_dictionary(data):
    tokens = [b".", b"..", b"0", b"255", b"256", b"-1", b"999", b"00", b"01", b"0x00", b" ", b"\n"]
    if not data: return random.choice(tokens)
    res = bytearray(data)
    idx = random.randint(0, len(res))
    return bytes(res[:idx] + random.choice(tokens) + res[idx:])

def mut_delete_chunk(data):
    if len(data) < 2: return data
    res = bytearray(data)
    start = random.randint(0, len(res) - 1)
    end = start + random.randint(1, min(16, len(res) - start))
    del res[start:end]
    return bytes(res)

operators = [mut_bitflip, mut_arithmetic, mut_interest, mut_dictionary, mut_delete_chunk]

# --- 3. MOPT Scheduler ---
class MOPT_Scheduler:
    def __init__(self, operators, window_size=100): # Lowered window size for single-thread speed
        self.operators = operators
        self.num_ops = len(operators)
        self.probabilities = np.full(self.num_ops, 1.0 / self.num_ops)
        self.total_successes = np.zeros(self.num_ops)
        self.total_selections = np.zeros(self.num_ops)
        self.epoch_successes = np.zeros(self.num_ops)
        self.epoch_selections = np.zeros(self.num_ops)
        self.window_size = window_size
        self.iterations = 0

    def select_operator(self):
        idx = np.random.choice(self.num_ops, p=self.probabilities)
        self.epoch_selections[idx] += 1
        self.total_selections[idx] += 1
        self.iterations += 1
        return self.operators[idx], idx

    def update_probabilities(self, op_idx, was_interesting):
        if was_interesting:
            self.epoch_successes[op_idx] += 1
            self.total_successes[op_idx] += 1
        
        if self.iterations % self.window_size == 0:
            efficiencies = np.zeros(self.num_ops)
            for i in range(self.num_ops):
                if self.epoch_selections[i] > 0:
                    efficiencies[i] = self.epoch_successes[i] / self.epoch_selections[i]
            
            if np.sum(efficiencies) == 0:
                self.probabilities = (self.probabilities * 0.9) + (0.1 / self.num_ops)
            else:
                efficiencies /= np.sum(efficiencies)
                self.probabilities = (0.8 * self.probabilities) + (0.2 * efficiencies)
            
            self.probabilities = np.maximum(self.probabilities, 0.05)
            self.probabilities /= np.sum(self.probabilities)
            self.epoch_successes.fill(0)
            self.epoch_selections.fill(0)

# --- 4. Coverage Tracker & Dashboard ---
class CoverageTracker:
    def __init__(self):
        self.global_blocks = set()

    def check_new_coverage(self, hits):
        new_found = False
        for block in hits:
            if block not in self.global_blocks:
                self.global_blocks.add(block)
                new_found = True
        return new_found

def save_crash(data, category="crash"):
    os.makedirs("crashes", exist_ok=True)
    data_hash = hashlib.md5(data).hexdigest()
    with open(f"crashes/{category}_{data_hash}.bin", "wb") as f:
        f.write(data)

class FuzzerDashboard:
    def __init__(self):
        self.iterations = 0
        self.start_time = time.time()
        self.total_crashes = 0

    def show(self, tracker, scheduler):
        os.system('cls' if os.name == 'nt' else 'clear')
        elapsed = time.time() - self.start_time
        speed = self.iterations / elapsed if elapsed > 0 else 0
        
        print("="*50)
        print(f" SEQUENTIAL FUZZER - STABLE BUILD")
        print("="*50)
        print(f" Executions: {self.iterations:<10} | Speed: {speed:.2f} exec/s")
        print(f" Crashes:    {self.total_crashes:<10} | Blocks Hit: {len(tracker.global_blocks)}")
        print("-" * 50)
        for i, op in enumerate(scheduler.operators):
            print(f"  {op.__name__:<18}: {scheduler.probabilities[i]:.4f}")
        print("="*50)

# --- 5. Single Execution Logic (STREAMING & DETACH DETECTION) ---
def run_one_process(target_command, mutated_input, device, tracker):
    payload_str = mutated_input.decode('latin-1', errors='replace')
    cmd = [arg.format(payload_str) if "{}" in arg else arg for arg in target_command]
    
    child_caught_event = threading.Event()
    session_detached = threading.Event()
    result = {"new_cov": False, "crashed": False}
    
    child_pid = [None]

    # Catch the streaming coverage updates from JS
    def on_message(message, data):
        if message['type'] == 'send' and message['payload']['type'] == 'coverage_update':
            hits = message['payload']['hits']
            if tracker.check_new_coverage(hits):
                result["new_cov"] = True

    def on_child_added(child):
        child_pid[0] = child.pid
        try:
            child_session = device.attach(child.pid)
            
            # Listen for the exact moment the process dies naturally
            def on_detached(reason):
                session_detached.set()
            child_session.on('detached', on_detached)
            
            with open("fuzzer_hook.js", "r") as f:
                script = child_session.create_script(f.read())
            
            script.on('message', on_message)
            script.load()
            device.resume(child.pid)
            child_caught_event.set()
        except Exception as e:
            child_caught_event.set()

    device.on('child-added', on_child_added)
    parent_pid = None

    try:
        parent_pid = device.spawn(cmd)
        parent_session = device.attach(parent_pid)
        parent_session.enable_child_gating()
        device.resume(parent_pid)
        
        # 1. Wait for the Bootloader to spawn the child
        if child_caught_event.wait(timeout=10.0):
            
            # 2. Wait for the program to finish and detach naturally (Max 5 seconds)
            is_dead = session_detached.wait(timeout=10.0)
            
            # If the session didn't detach within 5 seconds, it's a true hang/crash
            if not is_dead:
                result["crashed"] = True
                
        else:
            result["crashed"] = True
            
    except frida.ProcessNotFoundError:
        result["crashed"] = True
    except Exception as e:
        result["crashed"] = True
    finally:
        device.off('child-added', on_child_added)
        
        # Hard kill to prevent %TEMP% folder locking
        if child_pid[0]:
            try: psutil.Process(child_pid[0]).kill()
            except: pass
        if parent_pid:
            try: psutil.Process(parent_pid).kill()
            except: pass

    return result["new_cov"], result["crashed"]

# --- 6. Main Loop ---
def main():
    set_reproducibility(42)
    
    # Command array. The "{}" will be replaced by the mutated input.
    target_command = ["./win-ipv4-parser.exe", "--ipstr", "{}"]
    
    loader = CorpusLoader("corpus_temp")
    scheduler = MOPT_Scheduler(operators)
    tracker = CoverageTracker()
    dashboard = FuzzerDashboard()
    device = frida.get_local_device()
    
    print("[*] Starting Sequential Process Fuzzer...")
    
    while True:
        seed = loader.get_random_seed()
        op, op_idx = scheduler.select_operator()
        mutated_input = op(seed)
        
        if not mutated_input: continue
        
        # Run one full lifecycle of the target
        new_cov, crashed = run_one_process(target_command, mutated_input, device, tracker)

        # Process Results
        scheduler.update_probabilities(op_idx, new_cov)
        
        if new_cov:
            loader.seeds.append(mutated_input)
            
        if crashed:
            dashboard.total_crashes += 1
            save_crash(mutated_input, "crash")

        # Update display (Lowered modulo so it updates visually faster since executions are slower)
        dashboard.iterations += 1
        if dashboard.iterations % 2 == 0:
            dashboard.show(tracker, scheduler)

if __name__ == "__main__":
    main()