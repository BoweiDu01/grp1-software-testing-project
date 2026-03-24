import os
import random
import numpy as np
import frida
import sys
import time
import hashlib
import psutil 

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

    def select_operator(self):
        idx = np.random.choice(len(self.operators), p=self.probabilities)
        self.selections[idx] += 1
        return self.operators[idx], idx

    def update_probabilities(self, op_idx, was_interesting):
        if was_interesting:
            self.successes[op_idx] += 1
        total_selections = np.sum(self.selections)
        if total_selections % 100 == 0:
            for i in range(len(self.operators)):
                efficiency = self.successes[i] / (self.selections[i] + 1)
                self.probabilities[i] = efficiency
            self.probabilities += self.epsilon
            self.probabilities /= self.probabilities.sum()

# --- 4. Coverage Tracker ---
current_test_data = b""

class CoverageTracker:
    def __init__(self):
        self.global_coverage = set()
        self.new_block_found = False
        self.min_distances = {}
        self.new_distance_record = False

    def on_message(self, message, data):
        global current_test_data 
        global dashboard      

        if message['type'] == 'send':
            payload = message['payload']
            if payload['type'] == 'new_block':
                addr = payload['address']
                if addr not in self.global_coverage:
                    self.global_coverage.add(addr)
                    self.new_block_found = True

            elif payload['type'] == 'cmp_distance':
                addr = payload['address']
                dist = payload['distance']
                if addr not in self.min_distances or dist < self.min_distances[addr]:
                    self.min_distances[addr] = dist
                    self.new_distance_record = True
        # In your CoverageTracker.on_message
        elif message['type'] == 'error':
            desc = str(message.get('description', ""))
            logic_errors = ["FunctionalBug", "InvalidityBug", "ParseException"]
            
            if any(error in desc for error in logic_errors):
                dashboard.total_bugs += 1 # Increment every time a bug/exception is hit
                self.new_block_found = True 
                save_crash(current_test_data, "logic_bug")
                return

            # Only save if it's a real memory corruption/system failure
            save_crash(current_test_data, "fatal_system_crash")


# --- 5. Execution Logic (Unused, can remove later)--- 
# def run_target_with_timeout(binary_path, input_data, timeout=5):
#     tracker.new_block_found = False
#     tracker.new_distance_record = False
#     start_time = time.time()
    
#     # 1. Spawn the parent normally
#     try:
#         pid = frida.spawn([binary_path, "--ipstr", input_data.decode(errors='ignore')])
#         frida.resume(pid) # Let the parent start extracting
        
#         # 2. Wait and "Hunt" for the child process
#         # PyInstaller usually names the child the same as the parent
#         child_pid = None
#         target_name = os.path.basename(binary_path)
            
#         search_start = time.time()
#         while (time.time() - search_start) < 2.0: # Search for 2 seconds
#             for proc in psutil.process_iter(['pid', 'name']):
#                 if proc.info['name'] == target_name and proc.info['pid'] != pid:
#                     child_pid = proc.info['pid']
#                     break
#             if child_pid: break
#             time.sleep(0.05)

#         # 3. Attach to whichever one we found (Child preferred, Parent fallback)    
#         attach_pid = child_pid if child_pid else pid
#         session = frida.attach(attach_pid)
        
#         with open("fuzzer_hook.js", "r") as f:
#             script = session.create_script(f.read())
        
#         script.on('message', tracker.on_message)
#         script.load()
        
#         # 4. Monitor Loop
#         while True:
#             if not psutil.pid_exists(attach_pid):
#                 time.sleep(0.3)
#                 break
                
#             if (time.time() - start_time) > timeout:
#                 try:
#                     p = psutil.Process(attach_pid)
#                     p.kill()
#                     if child_pid: psutil.Process(pid).kill()
#                 except: pass
#                 return "hang", timeout
            
#             time.sleep(0.1)
            
#         return "success", time.time() - start_time

#     except Exception as e:
#         print(f"Error: {e}")
#         return "error", 0

# --- 6. Stats & Dashboard ---
class PerformanceStats:
    def __init__(self):
        self.history = []
    def is_outlier(self, current_time):
        if len(self.history) < 20:
            self.history.append(current_time)
            return False
        avg = sum(self.history) / len(self.history)
        if current_time > (avg * 3): return True
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
        os.system('cls' if os.name == 'nt' else 'clear')
        elapsed = time.time() - self.start_time
        speed = self.iterations / elapsed if elapsed > 0 else 0
        
        # Calculate Bug Density (Bugs per 100 iterations)
        bug_density = (self.total_bugs / self.iterations * 100) if self.iterations > 0 else 0
        
        print("="*50)
        print(f" CUSTOM FUZZER - 2  win_ipv4_parser.exe")
        print("="*50)
        print(f" Iterations: {self.iterations:<10} | Speed: {speed:.2f} exec/s")
        print(f" Total Bugs: {self.total_bugs:<10} | Hit Rate: {bug_density:.2f}%")
        print(f" Blocks: {len(tracker.global_coverage):<14} | Edges: {len(tracker.min_distances)}")
        print("-" * 50)
        for i, op in enumerate(scheduler.operators):
            print(f"  {op.__name__:<18}: {scheduler.probabilities[i]:.4f}")
        print("="*50)

class PersistentFuzzer:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.device = frida.get_local_device()
        
        # We need to track the active script (the one inside the CHILD)
        self.active_script = None 
        self.child_pid = None
        self.parent_pid = None
        
        # 1. Register the listener for child processes
        self.device.on('child-added', self.on_child_added)
        
        self.start_session()

    def on_child_added(self, child):
        print(f"[*] REAL PARSER DETECTED! (PID: {child.pid})")
        self.child_pid = child.pid
        
        try:
            # 2. Attach to the child immediately
            session = self.device.attach(child.pid)
            with open("fuzzer_hook.js", "r") as f:
                script = session.create_script(f.read())
            
            script.on('message', tracker.on_message)
            script.load()
            
            # 3. Save this script so run_one() can use it
            self.active_script = script
            
            # 4. Let the child run!
            self.device.resume(child.pid)
        except Exception as e:
            print(f"[!] Error hooking child: {e}")

    def start_session(self):
        try:
            # Kill leftovers
            if self.parent_pid:
                try: psutil.Process(self.parent_pid).kill()
                except: pass

            print(f"[*] Spawning Bootloader: {self.binary_path}")
            self.parent_pid = self.device.spawn([self.binary_path])
            
            # 5. Attach to parent and ENABLE GATING
            parent_session = self.device.attach(self.parent_pid)
            parent_session.enable_child_gating()
            
            # Resume parent so it can extract the child
            self.device.resume(self.parent_pid)
            
            # 6. Wait for the child to spawn and the hook to load
            print("[*] Waiting for child extraction...")
            timeout = 10
            start = time.time()
            while self.active_script is None:
                if (time.time() - start) > timeout:
                    print("[!] Timeout waiting for child process.")
                    self.restart()
                    break
                time.sleep(0.5)
                
        except Exception as e:
            print(f"[!] Failed to start session: {e}")
            sys.exit(1)

    def restart(self):
        print("[!] Restarting entire process chain...")
        self.active_script = None
        self.start_session()

    def run_one(self, data):
        global dashboard # Ensure we can reach the dashboard
        tracker.new_block_found = False
        
        if not self.active_script:
            return "error", 0

        try:
            self.active_script.exports.fuzz(list(data)) 
            return "success", 0
        except Exception as e:
            # THIS is where fatal crashes land
            dashboard.total_bugs += 1  # <--- ADD THIS LINE
            save_crash(data, "fatal_system_crash")
            self.restart()
            return "crash", 0

tracker = CoverageTracker()
dashboard = FuzzerDashboard()  
# --- 7. Main Loop ---
def main():
    set_reproducibility(42)
    binary_path = "./win-ipv4-parser.exe"
    global current_test_data
    loader = CorpusLoader("corpus")
    scheduler = MOPT_Scheduler(operators)
    fuzzer_engine = PersistentFuzzer("./win-ipv4-parser.exe")
    
    while True:
        seed = loader.get_random_seed()
        op, op_idx = scheduler.select_operator()
        
        if op == mut_splice:
            mutated_input = op(seed, loader.get_random_seed())
        else:
            mutated_input = op(seed)
        
        current_test_data = mutated_input
        status, elapsed = fuzzer_engine.run_one(mutated_input)
        
        if status == "error": continue

        is_interesting, tier = check_interesting(status, elapsed, tracker.new_block_found, tracker.new_distance_record)

        if is_interesting:
            scheduler.update_probabilities(op_idx, True)
            loader.seeds.append(mutated_input)
            
            
        dashboard.iterations += 1
        if dashboard.iterations % 5 == 0:
            dashboard.show(tracker, scheduler)

if __name__ == "__main__":
    main()