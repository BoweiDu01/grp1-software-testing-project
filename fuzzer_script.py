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
    if not data:
        return data
    res = bytearray(data)
    idx = random.randint(0, len(res) - 1)
    res[idx] ^= (1 << random.randint(0, 7))
    return bytes(res)


def mut_arithmetic(data):
    if not data:
        return data
    res = bytearray(data)
    idx = random.randint(0, len(res) - 1)
    val = random.randint(-35, 35)
    res[idx] = (res[idx] + val) % 256
    return bytes(res)


def mut_interest(data):
    if not data:
        return data
    interesting = [0, 1, 127, 128, 255, 0xffff, 0xffffffff]
    res = bytearray(data)
    idx = random.randint(0, len(res) - 1)
    val = random.choice(interesting)
    res[idx] = val % 256
    return bytes(res)


def mut_dictionary(data):
    tokens = [b"{", b"}", b"[", b"]", b":", b",", b"127.0.0.1", b"::1"]
    if not data:
        return random.choice(tokens)
    res = bytearray(data)
    idx = random.randint(0, len(res))
    token = random.choice(tokens)
    return bytes(res[:idx] + token + res[idx:])


def mut_delete_chunk(data):
    if len(data) < 2:
        return data
    res = bytearray(data)
    start = random.randint(0, len(res) - 1)
    end = start + random.randint(1, min(16, len(res) - start))
    del res[start:end]
    return bytes(res)


def mut_splice(data, other_seed):
    if not data or not other_seed:
        return data
    idx1 = random.randint(0, len(data))
    idx2 = random.randint(0, len(other_seed))
    return data[:idx1] + other_seed[idx2:]


operators = [mut_bitflip, mut_arithmetic, mut_interest,
             mut_dictionary, mut_delete_chunk, mut_splice]

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

    def update_probabilities(self, op_idx, reward):
        if reward > 0:
            self.successes[op_idx] += reward
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
        self.global_edges = set()
        self.new_block_found = False
        self.new_edge_found = False
        self.min_distances = {}
        self.new_distance_record = False
        self.path_depth = 0
        self.best_path_depth = 0
        self.path_depth_increased = False
        self.max_loop_iterations = 0
        self.best_loop_iterations = 0
        self.loop_iterations_increased = False
        self.last_exception_text = ""
        self.last_output_category = "none"
        self.new_output_category = False
        self.seen_output_categories = set(["none"])
        self.last_run_blocks = []
        self.last_bug_fingerprint = None
        self.seen_path_signatures = set()
        self.new_path_signature = False
        self.message_counts = {
            "new_block": 0,
            "batch_edges": 0,
            "cmp_distance": 0,
            "batch_cmps": 0,
            "run_metrics": 0
        }
        self.total_metric_messages = 0
        self.hook_ready = False
        self.hook_target = ""

    def start_iteration(self):
        self.new_block_found = False
        self.new_edge_found = False
        self.new_distance_record = False
        self.path_depth_increased = False
        self.loop_iterations_increased = False
        self.new_output_category = False
        self.new_path_signature = False
        self.last_exception_text = ""
        self.last_output_category = "none"
        self.last_run_blocks = []
        self.last_bug_fingerprint = None

    def build_bug_fingerprint(self):
        text = (self.last_exception_text or "").strip().lower()
        if not text:
            text = self.last_output_category or "unknown"
        blocks = "|".join(self.last_run_blocks[:8])
        raw = f"{text}::{blocks}"
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()

    def classify_output_category(self, text):
        t = (text or "").lower()
        if not t:
            return "none"
        if "performance" in t or "latency" in t or "slow" in t or "timeout" in t:
            return "performance_bug"
        if "fatal" in t or "segfault" in t or "access violation" in t:
            return "fatal_exception"
        if "parse" in t or "invalid ip" in t or "functionalbug" in t or "invaliditybug" in t:
            return "parse_or_functional_bug"
        if "oom" in t or "out of memory" in t or "memory" in t:
            return "memory_bug"
        return "other_output"

    def _track_output_category(self, text):
        category = self.classify_output_category(text)
        self.last_output_category = category
        if category not in self.seen_output_categories:
            self.seen_output_categories.add(category)
            self.new_output_category = True

    def on_message(self, message, data):
        global current_test_data
        global dashboard

        if message['type'] == 'send':
            payload = message['payload']
            ptype = payload.get('type')

            if ptype == 'hook_status':
                self.hook_ready = payload.get('status') == 'ok'
                self.hook_target = str(payload.get('target', ''))
                return

            if payload['type'] == 'new_block':
                self.message_counts["new_block"] += 1
                self.total_metric_messages += 1
                addr = payload['address']
                if addr not in self.global_coverage:
                    self.global_coverage.add(addr)
                    self.new_block_found = True

            elif payload['type'] == 'batch_edges':
                self.message_counts["batch_edges"] += 1
                self.total_metric_messages += 1
                edges = payload.get('edges', [])
                for edge in edges:
                    edge_str = str(edge)
                    if edge_str not in self.global_edges:
                        self.global_edges.add(edge_str)
                        self.new_edge_found = True
                    parts = edge_str.split('->', 1)
                    if len(parts) == 2:
                        dst = parts[1]
                        if dst not in self.global_coverage:
                            self.global_coverage.add(dst)
                            self.new_block_found = True

            elif payload['type'] == 'cmp_distance':
                self.message_counts["cmp_distance"] += 1
                self.total_metric_messages += 1
                addr = payload['address']
                dist = payload['distance']
                if addr not in self.min_distances or dist < self.min_distances[addr]:
                    self.min_distances[addr] = dist
                    self.new_distance_record = True

            elif payload['type'] == 'batch_cmps':
                self.message_counts["batch_cmps"] += 1
                self.total_metric_messages += 1
                entries = payload.get('entries', [])
                for entry in entries:
                    addr = str(entry.get('address', ''))
                    dist = int(entry.get('distance', 0))
                    if not addr:
                        continue
                    if addr not in self.min_distances or dist < self.min_distances[addr]:
                        self.min_distances[addr] = dist
                        self.new_distance_record = True

            elif payload['type'] == 'run_metrics':
                self.message_counts["run_metrics"] += 1
                self.total_metric_messages += 1
                self.path_depth = int(payload.get('path_depth', 0))
                self.max_loop_iterations = int(
                    payload.get('max_loop_iterations', 0))
                self.last_run_blocks = [str(b)
                                        for b in payload.get('top_blocks', [])]
                if self.last_run_blocks:
                    signature_raw = "|".join(self.last_run_blocks)
                    signature = hashlib.sha256(signature_raw.encode(
                        "utf-8", errors="ignore")).hexdigest()
                    if signature not in self.seen_path_signatures:
                        self.seen_path_signatures.add(signature)
                        self.new_path_signature = True
                if self.path_depth > self.best_path_depth:
                    self.best_path_depth = self.path_depth
                    self.path_depth_increased = True
                if self.max_loop_iterations > self.best_loop_iterations:
                    self.best_loop_iterations = self.max_loop_iterations
                    self.loop_iterations_increased = True
            elif payload['type'] == 'crash':
                text = str(payload.get('error', ''))
                self.last_exception_text = text
                self._track_output_category(text)
            elif payload['type'] == 'output':
                text = str(payload.get('text', ''))
                self._track_output_category(text)
        # In your CoverageTracker.on_message
        elif message['type'] == 'error':
            desc = str(message.get('description', ""))
            self.last_exception_text = desc
            self._track_output_category(desc)
            logic_errors = ["FunctionalBug", "InvalidityBug",
                            "ParseException", "fatal", "access violation"]

            if any(error in desc for error in logic_errors):
                self.new_block_found = True
                return

            # Only save if it's a real memory corruption/system failure
            return


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
        self.exec_history = []
        self.mem_history = []

    def is_exec_outlier(self, current_time):
        if len(self.exec_history) < 20:
            self.exec_history.append(current_time)
            return False
        avg = sum(self.exec_history) / len(self.exec_history)
        if current_time > (avg * 3):
            self.exec_history.append(current_time)
            return True
        self.exec_history.append(current_time)
        return False

    def is_memory_spike(self, mem_kb):
        if len(self.mem_history) < 20:
            self.mem_history.append(mem_kb)
            return False
        avg = sum(self.mem_history) / len(self.mem_history)
        if mem_kb > (avg * 2):
            self.mem_history.append(mem_kb)
            return True
        self.mem_history.append(mem_kb)
        return False


stats = PerformanceStats()


def is_tier1(status, exception_text):
    fatal_tokens = ["fatal", "access violation", "segfault", "crash"]
    text = (exception_text or "").lower()
    if status in ["crash", "fatal_exception", "hang"]:
        return True
    return any(tok in text for tok in fatal_tokens)


def check_interesting(status, exec_time, mem_spike, tracker):
    # Tier 1: Highest priority, triage only (do not mutate)
    if is_tier1(status, tracker.last_exception_text):
        return True, "tier_1", "fatal_or_crash"

    # Ignore infrastructure/runtime transport failures.
    if status != "success":
        return False, None, None

    # Tier 2: Exploration progress, high mutation energy
    if tracker.new_block_found:
        return True, "tier_2", "new_coverage"
    if tracker.new_edge_found:
        return True, "tier_2", "new_edge"
    if tracker.new_distance_record:
        return True, "tier_2", "reduced_cmp_distance"
    if tracker.new_path_signature:
        return True, "tier_2", "new_path_signature"
    if tracker.path_depth_increased:
        return True, "tier_2", "increased_path_depth"
    if tracker.loop_iterations_increased:
        return True, "tier_2", "increased_loop_iterations"

    # Tier 3: Anomalies and new behavior categories
    if stats.is_exec_outlier(exec_time):
        return True, "tier_3", "exec_time_outlier"
    if mem_spike:
        return True, "tier_3", "memory_spike"
    if tracker.new_output_category:
        return True, "tier_3", f"new_output_category:{tracker.last_output_category}"

    return False, None, None


def mutation_reward_for_tier(tier):
    if tier == "tier_2":
        return 3.0
    if tier == "tier_3":
        return 1.0
    return 0.0


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
        self.total_bug_hits = 0
        self.unique_bug_count = 0
        self.unique_bug_fingerprints = set()
        self.tier_hits = {"tier_1": 0, "tier_2": 0, "tier_3": 0}
        self.category_hits = {}

    def show(self, tracker, scheduler, bug_csv="bug_counts.csv"):
        os.system('cls' if os.name == 'nt' else 'clear')
        elapsed = time.time() - self.start_time
        speed = self.iterations / elapsed if elapsed > 0 else 0

        # Calculate Bug Density (Bugs per 100 iterations)
        bug_density = (self.total_bug_hits / self.iterations *
                       100) if self.iterations > 0 else 0

        print("="*50)
        print(f" CUSTOM FUZZER - 2  win_ipv4_parser.exe")
        print("="*50)
        print(
            f" Iterations: {self.iterations:<10} | Speed: {speed:.2f} exec/s")
        print(
            f" Bug Hits: {self.total_bug_hits:<11} | Unique Bugs: {self.unique_bug_count}")
        print(f" Hit Rate: {bug_density:.2f}%")
        print(
            f" Blocks: {len(tracker.global_coverage):<14} | Edges: {len(tracker.global_edges)}")
        print(
            f" PathDepth: {tracker.best_path_depth:<10} | MaxLoop: {tracker.best_loop_iterations}")
        print(
            f" HookReady: {tracker.hook_ready!s:<8} | MetricsMsg: {tracker.total_metric_messages}")
        print(
            f" Tier1: {self.tier_hits['tier_1']:<4} Tier2: {self.tier_hits['tier_2']:<4} Tier3: {self.tier_hits['tier_3']:<4}")
        print("-" * 50)
        for i, op in enumerate(scheduler.operators):
            print(f"  {op.__name__:<18}: {scheduler.probabilities[i]:.4f}")
        print("="*50)


def sample_process_memory_kb(pid):
    try:
        p = psutil.Process(pid)
        return int(p.memory_info().rss / 1024)
    except Exception:
        return 0


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
                try:
                    psutil.Process(self.parent_pid).kill()
                except:
                    pass

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
        global dashboard  # Ensure we can reach the dashboard
        tracker.start_iteration()

        if not self.active_script:
            return "error", 0.0, 0

        try:
            start = time.time()
            mem_before = sample_process_memory_kb(
                self.child_pid) if self.child_pid else 0
            self.active_script.exports.fuzz(list(data))
            mem_after = sample_process_memory_kb(
                self.child_pid) if self.child_pid else 0
            elapsed = time.time() - start
            rss_delta = max(0, mem_after - mem_before)
            return "success", elapsed, rss_delta
        except frida.InvalidOperationError:
            # Session/script lifecycle issue (not a target bug).
            self.restart()
            return "error", 0.0, 0
        except Exception as e:
            # THIS is where fatal crashes land
            tracker.last_exception_text = str(e)
            tracker._track_output_category(str(e))
            self.restart()
            return "crash", 0.0, 0


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
    stale_metric_iters = 0
    last_metric_total = tracker.total_metric_messages
    stale_limit = 200

    while True:
        seed = loader.get_random_seed()
        op, op_idx = scheduler.select_operator()

        if op == mut_splice:
            mutated_input = op(seed, loader.get_random_seed())
        else:
            mutated_input = op(seed)

        current_test_data = mutated_input
        status, elapsed, rss_delta = fuzzer_engine.run_one(mutated_input)

        if tracker.total_metric_messages == last_metric_total:
            stale_metric_iters += 1
        else:
            stale_metric_iters = 0
            last_metric_total = tracker.total_metric_messages

        if stale_metric_iters >= stale_limit:
            raise RuntimeError(
                "Telemetry appears inactive: no coverage/run-metrics messages received for "
                f"{stale_limit} iterations. Check hook target resolution and child-process attach."
            )

        if status == "error":
            continue

        mem_spike = stats.is_memory_spike(rss_delta)
        is_interesting, tier, reason = check_interesting(
            status, elapsed, mem_spike, tracker)

        if is_interesting:
            dashboard.tier_hits[tier] += 1
            if reason:
                dashboard.category_hits[reason] = dashboard.category_hits.get(
                    reason, 0) + 1

            if tier == "tier_1":
                dashboard.total_bug_hits += 1
                fingerprint = tracker.build_bug_fingerprint()
                is_new_bug = fingerprint not in dashboard.unique_bug_fingerprints
                if is_new_bug:
                    dashboard.unique_bug_fingerprints.add(fingerprint)
                    dashboard.unique_bug_count += 1
                    category = tracker.last_output_category if tracker.last_output_category != "none" else "fatal_system_crash"
                    save_crash(mutated_input,
                               f"{category}_u{dashboard.unique_bug_count}")
            else:
                scheduler.update_probabilities(
                    op_idx, mutation_reward_for_tier(tier))
                loader.seeds.append(mutated_input)
        else:
            scheduler.update_probabilities(op_idx, 0.0)

        dashboard.iterations += 1
        if dashboard.iterations % 5 == 0:
            dashboard.show(tracker, scheduler)


if __name__ == "__main__":
    main()
