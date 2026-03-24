import os
import random
import numpy as np
import frida
import sys
import time
import hashlib
import psutil
from collections import deque

def set_reproducibility(seed_value=42):
    random.seed(seed_value)
    np.random.seed(seed_value)
    # If you use random.choice elsewhere, this locks it globally
    print(f"[*] Fuzzing with Fixed Seed: {seed_value}")

# --- 1. Corpus Loader ---
class CorpusLoader:
    def __init__(self, corpus_dir):
        self.seeds = []
        if not os.path.exists(corpus_dir):
            print(f"Error: Corpus directory {corpus_dir} not found.")
            sys.exit(1)
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
    tokens = [b"{", b"}", b"[", b"]", b":", b",", b"127.0.0.1", b"::1"]
    if not data: return random.choice(tokens)
    res = bytearray(data)
    idx = random.randint(0, len(res))
    token = random.choice(tokens)
    return bytes(res[:idx] + token + res[idx:])

def mut_delete_chunk(data):
    if len(data) < 2: return data
    res = bytearray(data)
    start = random.randint(0, len(res) - 1)
    end = start + random.randint(1, min(16, len(res) - start))
    del res[start:end]
    return bytes(res)

def mut_splice(data, other_seed):
    if not data or not other_seed: return data
    idx1 = random.randint(0, len(data))
    idx2 = random.randint(0, len(other_seed))
    return data[:idx1] + other_seed[idx2:]

operators = [mut_bitflip, mut_arithmetic, mut_interest, mut_dictionary, mut_delete_chunk, mut_splice]

# --- 3. MOPT Scheduler ---
class MOPT_Scheduler:
    def __init__(self, operators):
        self.operators = operators
        self.probabilities = np.full(len(operators), 1.0 / len(operators))
        self.successes = np.zeros(len(operators))
        self.selections = np.zeros(len(operators))
        self.epsilon = 0.1
        self._total_selections = 0  # plain int avoids np.sum every call

    def select_operator(self):
        idx = np.random.choice(len(self.operators), p=self.probabilities)
        self.selections[idx] += 1
        self._total_selections += 1
        return self.operators[idx], idx

    def update_probabilities(self, op_idx, was_interesting):
        if was_interesting:
            self.successes[op_idx] += 1
        if self._total_selections % 100 == 0:
            for i in range(len(self.operators)):
                efficiency = self.successes[i] / (self.selections[i] + 1)
                self.probabilities[i] = efficiency
            self.probabilities += self.epsilon
            self.probabilities /= self.probabilities.sum()

# --- 4. Coverage Tracker ---
current_test_data = b""

class CoverageTracker:
    def __init__(self):
        self.global_edges = set()   # "src->dst" control-flow edge strings
        self.global_blocks = set()  # unique block addresses (derived from edges)
        self.new_coverage_found = False
        self.min_distances = {}
        self.new_distance_record = False

    def on_message(self, message, data):
        global current_test_data
        if message['type'] == 'send':
            payload = message['payload']
            if payload['type'] == 'batch_edges':
                for edge in payload['edges']:
                    if edge not in self.global_edges:
                        self.global_edges.add(edge)
                        self.new_coverage_found = True
                        # Track the destination block separately for display
                        self.global_blocks.add(edge.split('->')[1])

            elif payload['type'] == 'batch_cmps':
                for entry in payload['entries']:
                    addr = entry['address']
                    dist = entry['distance']
                    if addr not in self.min_distances or dist < self.min_distances[addr]:
                        self.min_distances[addr] = dist
                        self.new_distance_record = True

        elif message['type'] == 'error':
            desc = str(message.get('description', ""))
            logic_errors = ["FunctionalBug", "InvalidityBug", "ParseException"]

            if any(error in desc for error in logic_errors):
                dashboard.total_bugs += 1
                self.new_coverage_found = True
                save_crash(current_test_data, "logic_bug")
                return

            # Only save if it's a real memory corruption/system failure
            save_crash(current_test_data, "fatal_system_crash")

tracker = CoverageTracker()

# Cache hook script once at module load to avoid per-iteration file I/O
with open("fuzzer_hook.js", "r") as _f:
    _hook_script = _f.read()

# --- 5. Execution Logic ---
def run_target_with_timeout(binary_path, input_data, timeout=5):
    tracker.new_coverage_found = False
    tracker.new_distance_record = False
    start_time = time.time()

    try:
        # 1. Spawn suspended, attach, instrument — THEN resume.
        #    This avoids the race where the binary exits before we can attach.
        pid = frida.spawn([binary_path, "--ipstr", input_data.decode(errors='ignore')])
        session = frida.attach(pid)

        script = session.create_script(_hook_script)
        script.on('message', tracker.on_message)
        script.load()

        frida.resume(pid)  # start execution only after instrumentation is in place

        # 2. Monitor loop
        while True:
            if not psutil.pid_exists(pid):
                break

            if (time.time() - start_time) > timeout:
                try:
                    psutil.Process(pid).kill()
                except: pass
                return "hang", timeout

            time.sleep(0.05)

        session.detach()
        return "success", time.time() - start_time

    except Exception as e:
        print(f"Error: {e}")
        return "error", 0

# --- 6. Stats & Dashboard ---
class PerformanceStats:
    def __init__(self, window=20):
        self.history = deque(maxlen=window)
        self._running_sum = 0.0

    def is_outlier(self, current_time):
        if len(self.history) < self.history.maxlen:
            self._running_sum += current_time
            self.history.append(current_time)
            return False
        avg = self._running_sum / len(self.history)
        if current_time > (avg * 3):
            return True
        self._running_sum += current_time - self.history[0]
        self.history.append(current_time)
        return False

stats = PerformanceStats()

def check_interesting(status, exec_time, new_coverage, new_distance):
    # Tier 1: Fatal (True Hangs)
    if status == "hang": return True, "tier_1"
    # Tier 2: Progress (New Paths or better Distance)
    if new_coverage or new_distance: return True, "tier_2"
    # Tier 3: Statistical Outliers
    if stats.is_outlier(exec_time): return True, "tier_3"
    return False, None

def save_crash(data, category="crash"):
    os.makedirs("crashes", exist_ok=True)
    data_hash = hashlib.md5(data).hexdigest()
    filename = f"crashes/{category}_{data_hash}.bin"
    if not os.path.exists(filename):
        with open(filename, "wb") as f:
            f.write(data)
    print(f"[!] {category.upper()} saved.")

class FuzzerDashboard:
    def __init__(self):
        self.iterations = 0
        self.start_time = time.time()
        self.total_bugs = 0

    def show(self, tracker, scheduler, bug_csv="bug_counts.csv"):
        print('\033[2J\033[H', end='')  # ANSI clear — no subprocess spawn
        elapsed = time.time() - self.start_time
        speed = self.iterations / elapsed if elapsed > 0 else 0
        
        # Calculate Bug Density (Bugs per 100 iterations)
        bug_density = (self.total_bugs / self.iterations * 100) if self.iterations > 0 else 0
        
        print("="*50)
        print(f" GEMINI CUSTOM FUZZER - win_ipv4_parser.exe")
        print("="*50)
        print(f" Iterations: {self.iterations:<10} | Speed: {speed:.2f} exec/s")
        print(f" Total Bugs: {self.total_bugs:<10} | Hit Rate: {bug_density:.2f}%")
        print(f" Blocks: {len(tracker.global_blocks):<14} | Edges: {len(tracker.global_edges)}")
        print("-" * 50)
        for i, op in enumerate(scheduler.operators):
            print(f"  {op.__name__:<18}: {scheduler.probabilities[i]:.4f}")
        print("="*50)

# --- 7. Main Loop ---
def main():
    set_reproducibility(42)
    # binary_path = "./win-ipv4-parser.exe"
    binary_path = "./mac-ipv4-parser"
    global current_test_data
    loader = CorpusLoader("corpus_temp")
    scheduler = MOPT_Scheduler(operators)
    dashboard = FuzzerDashboard()
    
    while True:
        seed = loader.get_random_seed()
        op, op_idx = scheduler.select_operator()
        
        if op == mut_splice:
            mutated_input = op(seed, loader.get_random_seed())
        else:
            mutated_input = op(seed)
        
        current_test_data = mutated_input
        status, elapsed = run_target_with_timeout(binary_path, mutated_input)
        
        if status == "error": continue

        is_interesting, tier = check_interesting(status, elapsed, tracker.new_coverage_found, tracker.new_distance_record)

        scheduler.update_probabilities(op_idx, is_interesting)
        if is_interesting:
            loader.seeds.append(mutated_input)
            
            
        dashboard.iterations += 1
        if dashboard.iterations % 5 == 0:
            dashboard.show(tracker, scheduler)

if __name__ == "__main__":
    main()