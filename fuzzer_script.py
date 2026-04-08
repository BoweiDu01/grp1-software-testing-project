import os
import random
import numpy as np
import sys
import time
import hashlib
import subprocess

def set_reproducibility(seed_value=42):
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

# --- 2. Structure-Aware Mutators ---
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

def mut_octet_overflow(data):
    try:
        ip = data.decode('ascii')
        octets = ip.split('.')
        if not octets: return data
        idx = random.randint(0, len(octets) - 1)
        edge_cases = ["255", "256", "0", "-1", "999", "4294967295", "-2147483648", "00", "01"]
        octets[idx] = random.choice(edge_cases)
        return ".".join(octets).encode('ascii')
    except: return data

def mut_delimiter_mess(data):
    try:
        ip = data.decode('ascii')
        mutations = [ip.replace(".", "..", 1), ip.replace(".", "", 1), ip.replace(".", " ", 1), ip + ".", "." + ip]
        return random.choice(mutations).encode('ascii')
    except: return data

def mut_type_confusion(data):
    try:
        ip = data.decode('ascii')
        octets = ip.split('.')
        if not octets: return data
        idx = random.randint(0, len(octets) - 1)
        confusion = ["0xc0", "0xa8", "abc", "1.2", " ", "1e3", "NaN", "None"]
        octets[idx] = random.choice(confusion)
        return ".".join(octets).encode('ascii')
    except: return data

def mut_length_extension(data):
    try:
        ip = data.decode('ascii')
        extensions = [".1", ".1.1", "A" * 256, "%s%n%x", " /24", ":80"]
        return (ip + random.choice(extensions)).encode('ascii')
    except: return data

def mut_truncation(data):
    try:
        ip = data.decode('ascii')
        octets = ip.split('.')
        if len(octets) > 1:
            octets.pop(random.randint(0, len(octets) - 1))
            return ".".join(octets).encode('ascii')
        return ip[:-1].encode('ascii') if len(ip) > 1 else data
    except: return data

operators = [mut_bitflip, mut_arithmetic, mut_interest, mut_dictionary, mut_delete_chunk,mut_octet_overflow, mut_delimiter_mess, mut_type_confusion, mut_length_extension, mut_truncation]

# --- 3. MOPT Scheduler ---
# Window size determines how often does the scheduler update its probabilities based on recent performance.
#If set to 10, means after 10 executions it will change the probabilities accordingly
class MOPT_Scheduler:
    def __init__(self, operators, window_size=10):
        self.operators = operators
        self.num_ops = len(operators)
        self.probabilities = np.full(self.num_ops, 1.0 / self.num_ops)
        self.epoch_successes = np.zeros(self.num_ops)
        self.epoch_selections = np.zeros(self.num_ops)
        self.window_size = window_size
        self.iterations = 0

    def select_operator(self):
        idx = np.random.choice(self.num_ops, p=self.probabilities)
        self.epoch_selections[idx] += 1
        self.iterations += 1
        return self.operators[idx], idx

    def update_probabilities(self, op_idx, was_interesting):
        if was_interesting:
            self.epoch_successes[op_idx] += 1
        
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

# --- 4. Output-State Tracker (NOW README-AWARE) ---
class OutputTracker:
    def __init__(self):
        self.seen_outputs = set()
        self.unique_bug_signatures = set()
        self.total_crashes = 0
        self.total_unique_behaviors = 0
        self.total_bugs_found = 0

    def evaluate(self, stdout_str, stderr_str, return_code):
        is_interesting = False
        is_bug = False
        
        # Combine output to search for README bug signatures
        combined_output = f"{stdout_str}\n{stderr_str}".strip()
        
        # Hash outputs to keep memory footprint tiny
        out_hash = hashlib.md5(combined_output.encode('utf-8')).hexdigest()
        
        if out_hash not in self.seen_outputs:
            self.seen_outputs.add(out_hash)
            is_interesting = True
            self.total_unique_behaviors += 1
            
            # --- THE MAGIC: Search for target-specific bug signatures ---
            bug_keywords = ["TRACEBACK", "ParseException", "validity bug", "invalidity", "bonus"]
            if any(keyword in combined_output for keyword in bug_keywords):
                is_bug = True
                self.total_bugs_found += 1
                
                # Try to extract just the exception line to see if it's a NEW type of bug
                for line in combined_output.split('\n'):
                    if "pyparsing.exceptions" in line:
                        bug_sig = hashlib.md5(line.encode('utf-8')).hexdigest()
                        self.unique_bug_signatures.add(bug_sig)
                        break

        # If the app exits with a non-zero code (OS-level crash, very rare for this target)
        if return_code != 0 and return_code != 1: 
            self.total_crashes += 1
            is_interesting = True
            
        return is_interesting, is_bug, combined_output

def save_bug(data, output, category="bug"):
    os.makedirs("found_bugs", exist_ok=True)
    data_hash = hashlib.md5(data).hexdigest()
    with open(f"found_bugs/{category}_{data_hash}.txt", "w", encoding='utf-8') as f:
        f.write(f"Payload: {data}\n\nTarget Output:\n{output}")

def save_crash(data, output, category="crash"):
    os.makedirs("crashes", exist_ok=True)
    data_hash = hashlib.md5(data).hexdigest()
    with open(f"crashes/{category}_{data_hash}.txt", "w") as f:
        f.write(f"Payload: {data}\n\nOutput/Error:\n{output}")

# --- 5. Pure Subprocess Execution ---
def run_one_process(target_command, mutated_input):
    payload_str = mutated_input.decode('latin-1', errors='replace')
    cmd = [arg.format(payload_str) if "{}" in arg else arg for arg in target_command]
    
    try:
        # Bumped timeout to 10.0s to allow PyInstaller to extract and run
        # Added explicit encoding so Windows CLI doesn't choke on weird bytes
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=10.0, 
            encoding='latin-1', 
            errors='replace'
        )
        return result.stdout, result.stderr, result.returncode, False
        
    except subprocess.TimeoutExpired as e:
        # If it genuinely hangs past 10 seconds, grab whatever it managed to print!
        partial_out = e.stdout if e.stdout else "TIMEOUT"
        partial_err = e.stderr if e.stderr else "TIMEOUT"
        return partial_out, partial_err, -1, True
        
    except Exception as e:
        return "", str(e), -1, True
    
# --- 6. Main Loop & Dashboard ---
def main():
    set_reproducibility(70)
    target_command = ["./win-ipv4-parser.exe", "--ipstr", "{}"]
    
    loader = CorpusLoader("corpus_temp")
    scheduler = MOPT_Scheduler(operators)
    tracker = OutputTracker()
    start_time = time.time()
    
    print("[*] Starting Output-State Black-Box Fuzzer...")
    
    while True:
        seed = loader.get_random_seed()
        op, op_idx = scheduler.select_operator()
        mutated_input = op(seed)
        
        if not mutated_input: continue
        
        # Execute natively
        stdout, stderr, ret_code, is_timeout = run_one_process(target_command, mutated_input)

        if is_timeout:
            tracker.total_crashes += 1
            save_bug(mutated_input, "Process Timed Out", "hang")
            is_interesting = True
        else:
            # Check for specific bugs
            is_interesting, is_bug, combined_out = tracker.evaluate(stdout, stderr, ret_code)
            
            if is_bug:
                save_bug(mutated_input, combined_out, "logic_bug")
            elif ret_code != 0 and ret_code != 1:
                save_bug(mutated_input, combined_out, "fatal_crash")

        # Train MOPT Scheduler
        scheduler.update_probabilities(op_idx, is_interesting)
        
        if is_interesting:
            loader.seeds.append(mutated_input)
            
        # Dashboard Update
        if scheduler.iterations % 5 == 0:
            os.system('cls' if os.name == 'nt' else 'clear')
            elapsed = time.time() - start_time
            speed = scheduler.iterations / elapsed if elapsed > 0 else 0
            
            print("="*50)
            print(f" BLACK-BOX FUZZER - OUTPUT STATE EDITION")
            print("="*50)
            print(f" Executions: {scheduler.iterations:<10} | Speed: {speed:.2f} exec/s")
            print(f" Bugs Found: {tracker.total_bugs_found:<10} | Unique Bug Types: {len(tracker.unique_bug_signatures)}")
            print(f" OS Crashes: {tracker.total_crashes:<10} | Unique Behaviors: {tracker.total_unique_behaviors}")
            print("-" * 50)
            for i, operator in enumerate(scheduler.operators):
                print(f"  {operator.__name__:<20}: {scheduler.probabilities[i]:.4f}")
            print("="*50)

if __name__ == "__main__":
    main()