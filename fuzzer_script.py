import argparse
import base64
import csv
import hashlib
import json
import multiprocessing as mp
import os
import queue
import random
import re
import subprocess
import sys
import time
from collections import Counter

import numpy as np
import psutil


def set_reproducibility(seed_value=42):
    random.seed(seed_value)
    np.random.seed(seed_value)
    print(f"[*] Fuzzing with Fixed Seed: {seed_value}")


class CorpusLoader:
    def __init__(self, corpus_dir):
        self.seeds = []
        if not os.path.exists(corpus_dir):
            print(f"Error: Corpus directory {corpus_dir} not found.")
            sys.exit(1)
        for root, _, files in os.walk(corpus_dir):
            for file in files:
                path = os.path.join(root, file)
                with open(path, "rb") as f:
                    data = f.read()
                    if data:
                        self.seeds.append(data)
        if not self.seeds:
            print(f"Error: No non-empty seeds found in {corpus_dir}.")
            sys.exit(1)
        print(f"Loaded {len(self.seeds)} seeds.")

    def get_random_seed(self):
        return random.choice(self.seeds)

    def add_seed(self, new_seed, max_corpus_size):
        if not new_seed:
            return
        self.seeds.append(new_seed)
        if len(self.seeds) > max_corpus_size:
            self.seeds.pop(random.randrange(len(self.seeds)))


# --- Mutations (generalizable, not structure-specific) ---
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
    interesting = [0, 1, 127, 128, 255, 0x7FFFFFFF, 0xFFFFFFFF]
    res = bytearray(data)
    idx = random.randint(0, len(res) - 1)
    val = random.choice(interesting)
    res[idx] = val % 256
    return bytes(res)


def mut_dictionary(data):
    tokens = [
        b"{",
        b"}",
        b"[",
        b"]",
        b":",
        b",",
        b"127.0.0.1",
        b"::1",
        b"0.0.0.0",
        b"255.255.255.255",
        b"../",
        b"\x00",
    ]
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


def _mut_as_text(data):
    text = data.decode("utf-8", errors="ignore")
    if not text:
        text = "0.0.0.0"
    return text


def _mut_to_bytes(text):
    return text.encode("utf-8", errors="ignore")


def mut_string_repeat_chunk(data):
    text = _mut_as_text(data)
    if len(text) == 1:
        return _mut_to_bytes(text * random.randint(2, 4))

    start = random.randint(0, len(text) - 1)
    end = min(len(text), start + random.randint(1, min(6, len(text) - start)))
    chunk = text[start:end]
    repeat_count = random.randint(2, 4)
    mutated = text[:start] + (chunk * repeat_count) + text[end:]
    return _mut_to_bytes(mutated)


def mut_string_delimiter_cluster(data):
    text = _mut_as_text(data)
    delimiters = [".", ":", "/", "-", "_", ","]
    delim = random.choice(delimiters)
    cluster = delim * random.randint(2, 5)

    idx = random.randint(0, len(text))
    mutated = text[:idx] + cluster + text[idx:]
    return _mut_to_bytes(mutated)


def mut_string_numeric_jitter(data):
    text = _mut_as_text(data)
    digit_positions = [i for i, ch in enumerate(text) if ch.isdigit()]
    if not digit_positions:
        idx = random.randint(0, len(text))
        injected = str(random.randint(0, 999))
        return _mut_to_bytes(text[:idx] + injected + text[idx:])

    idx = random.choice(digit_positions)
    old_val = int(text[idx])
    new_val = str((old_val + random.randint(1, 9)) % 10)
    mutated = text[:idx] + new_val + text[idx + 1:]
    return _mut_to_bytes(mutated)


def mut_string_whitespace_noise(data):
    text = _mut_as_text(data)
    noise = random.choice([" ", "\t", "\n"])
    idx = random.randint(0, len(text))
    mutated = text[:idx] + (noise * random.randint(1, 3)) + text[idx:]
    return _mut_to_bytes(mutated)


operators = [
    mut_bitflip,
    mut_arithmetic,
    mut_interest,
    mut_dictionary,
    mut_delete_chunk,
    mut_splice,
    mut_string_repeat_chunk,
    mut_string_delimiter_cluster,
    mut_string_numeric_jitter,
    mut_string_whitespace_noise,
]


class PSO_MOpt:
    def __init__(self, num_particles, dim):
        self.num_particles = num_particles
        self.dim = dim

        # logits (better than raw probs)
        self.positions = np.random.randn(num_particles, dim)
        self.velocities = np.zeros((num_particles, dim))

        self.pbest_positions = self.positions.copy()
        self.pbest_scores = np.zeros(num_particles)

        self.gbest_position = self.positions[0].copy()
        self.gbest_score = -1

        # PSO params
        self.w = 0.7
        self.c1 = 1.5
        self.c2 = 1.5

        # reward tracking (important)
        self.current_rewards = np.zeros(num_particles)
        self.current_counts = np.zeros(num_particles)

        self.active_particle = 0

    def softmax(self, x):
        e = np.exp(x - np.max(x))
        return e / e.sum()

    def get_current_distribution(self):
        return self.softmax(self.positions[self.active_particle])

    def record_reward(self, reward):
        i = self.active_particle
        self.current_rewards[i] += reward
        self.current_counts[i] += 1

    def step_particle(self):
        i = self.active_particle

        if self.current_counts[i] > 0:
            score = self.current_rewards[i] / self.current_counts[i]

            # update pbest
            if score > self.pbest_scores[i]:
                self.pbest_scores[i] = score
                self.pbest_positions[i] = self.positions[i].copy()

            # update gbest
            if score > self.gbest_score:
                self.gbest_score = score
                self.gbest_position = self.positions[i].copy()

        # reset stats
        self.current_rewards[i] = 0
        self.current_counts[i] = 0

        # move to next particle
        self.active_particle = (self.active_particle + 1) % self.num_particles

    def update_swarm(self):
        for i in range(self.num_particles):
            r1, r2 = np.random.rand(), np.random.rand()

            self.velocities[i] = (
                self.w * self.velocities[i]
                + self.c1 * r1 * (self.pbest_positions[i] - self.positions[i])
                + self.c2 * r2 * (self.gbest_position - self.positions[i])
            )

            self.positions[i] += self.velocities[i]


class MOPT_Scheduler:
    def __init__(self, operators, update_interval=10):
        self.operators = operators
        self.update_interval = update_interval
        self.counter = 0

        self.pso = PSO_MOpt(
            num_particles=8,
            dim=len(operators)
        )

        self.probabilities = np.ones(
            len(self.operators), dtype=float) / max(1, len(self.operators))

    def select_operator(self):
        self.probabilities = self.pso.get_current_distribution()
        idx = np.random.choice(len(self.operators), p=self.probabilities)
        return self.operators[idx], idx

    def update_probabilities(self, op_idx, reward):
        # ignore op_idx → PSO works on full distribution
        self.pso.record_reward(reward)

        self.counter += 1

        if self.counter % self.update_interval == 0:
            self.pso.step_particle()

            # full swarm update once per cycle
            if self.pso.active_particle == 0:
                self.pso.update_swarm()


class PerformanceStats:
    def __init__(self):
        self.exec_history = []
        self.mem_history = []

    def is_exec_outlier(self, current_time):
        if len(self.exec_history) < 20:
            self.exec_history.append(current_time)
            return False
        avg = sum(self.exec_history) / len(self.exec_history)
        self.exec_history.append(current_time)
        return current_time > (avg * 3)

    def is_memory_spike(self, mem_kb):
        if len(self.mem_history) < 20:
            self.mem_history.append(mem_kb)
            return False
        avg = sum(self.mem_history) / len(self.mem_history)
        self.mem_history.append(mem_kb)
        return mem_kb > (avg * 2)


class CoverageTracker:
    def __init__(self):
        self.global_coverage = set()
        self.global_edges = set()
        self.min_distances = {}

        self.new_block_found = False
        self.new_edge_found = False
        self.new_distance_record = False
        self.path_depth_increased = False
        self.loop_iterations_increased = False
        self.new_output_category = False
        self.new_path_signature = False

        self.path_depth = 0
        self.best_path_depth = 0
        self.max_loop_iterations = 0
        self.best_loop_iterations = 0

        self.last_exception_text = ""
        self.last_output_category = "none"
        self.last_bug_fingerprint = None
        self.last_bug_signature = None

        self.seen_output_categories = {"none"}
        self.seen_path_signatures = set()
        self.seen_bug_fingerprints = set()

        self.message_counts = {
            "run_metrics": 0,
            "feature_extract": 0,
            "bug_extract": 0,
        }
        self.total_metric_messages = 0
        self.hook_ready = False
        self.hook_target = ""
        self._last_feature_id = None

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
        self.last_bug_fingerprint = None
        self.last_bug_signature = None

    def classify_output_category(self, text):
        t = (text or "").lower()
        if not t:
            return "none"
        if "timeout" in t or "slow" in t or "latency" in t:
            return "performance_bug"
        if "fatal" in t or "segfault" in t or "access violation" in t:
            return "fatal_exception"
        if "functional bug" in t or "invalidity bug" in t or "parseexception" in t:
            return "parse_or_functional_bug"
        if "out of memory" in t or "oom" in t or "memory" in t:
            return "memory_bug"
        return "other_output"

    def _track_output_category(self, text):
        category = self.classify_output_category(text)
        self.last_output_category = category
        if category not in self.seen_output_categories:
            self.seen_output_categories.add(category)
            self.new_output_category = True

    def normalize_output(self, text):
        normalized = text.lower()
        normalized = re.sub(r"0x[0-9a-f]+", "<hex>", normalized)
        normalized = re.sub(r"\b\d+\b", "<num>", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized

    def canonicalize_bug_fields(self, bug_type, exception_type, message, hinted_bug_type=""):
        btype = (bug_type or "other").lower()
        etype = exception_type or "UnknownException"
        msg = (message or "").strip()
        hinted = (hinted_bug_type or "").lower()

        # Collapse pyparsing location/token specifics into one semantic parser-failure bucket.
        if "parseexception" in etype.lower():
            etype = "ParseException"
            # Preserve explicit validity labeling when provided by the target output.
            if hinted == "validity" or btype == "validity":
                return "validity", etype, msg or "Semantically invalid IPv4 value"
            btype = "invalidity"
            return btype, etype, "IPv4 tokenization failure"

        # InvalidityBug usually carries many tiny variants; keep one canonical family label.
        if "invaliditybug" in etype.lower():
            btype = "invalidity"
            return btype, "InvalidityBug", "Malformed IPv4 structure"

        # ValidityBug often indicates semantically wrong-yet-parseable values.
        if "validitybug" in etype.lower():
            btype = "validity"
            return btype, "ValidityBug", "Semantically invalid IPv4 value"

        # Keep functional bug class, but normalize noisy wording differences.
        if "functionalbug" in etype.lower():
            btype = "functional"
            if "invalid ipv4 calculation" in msg.lower():
                msg = "Invalid IPv4 calculation"
            return btype, "FunctionalBug", msg or "Functional bug"

        return btype, etype, msg

    def extract_bug_signature(self, text, exit_code):
        raw = text or ""
        if not raw and exit_code == 0:
            return None, None

        bug_type_hint = ""
        bug_type_match = re.search(
            r"bug type\s*:\s*([a-z_]+)", raw, flags=re.IGNORECASE)
        if bug_type_match:
            candidate = bug_type_match.group(1).strip().lower()
            if candidate in {"validity", "invalidity", "functional", "parse"}:
                bug_type_hint = candidate

        exc_matches = re.findall(
            r"([\w\.]+(?:Error|Exception|Bug)):\s*(.+)", raw)
        file_matches = re.findall(r'File "([^\"]+)", line\s+(\d+)', raw)

        exception_type = ""
        message = ""
        if exc_matches:
            exception_type, message = exc_matches[-1]

        if not exception_type and "invalidity bug" in raw.lower():
            exception_type = "InvalidityBug"
            message = "invalidity bug triggered"

        if not exception_type and "functional bug" in raw.lower():
            exception_type = "FunctionalBug"
            message = "functional bug triggered"

        if not exception_type:
            return None, None

        file_name = "unknown"
        line_no = "0"
        if file_matches:
            file_name, line_no = file_matches[-1]

        # Use binary-owned bug counts as a stable bug_type hint for ParseException buckets.
        counts_hint = _lookup_bug_type_from_bug_counts(
            exception_type,
            message,
            file_name,
            line_no,
        )
        if counts_hint and not bug_type_hint:
            bug_type_hint = counts_hint

        bug_type = bug_type_hint or "other"
        if bug_type == "other":
            lowered = raw.lower()
            if "invalidity" in lowered:
                bug_type = "invalidity"
            elif "functional" in lowered:
                bug_type = "functional"
            elif "parseexception" in lowered:
                bug_type = "parse"

        bug_type, exception_type, message = self.canonicalize_bug_fields(
            bug_type,
            exception_type,
            message,
            hinted_bug_type=bug_type_hint,
        )

        signature = (bug_type, exception_type,
                     message.strip(), file_name, str(line_no))
        fingerprint = hashlib.sha256("||".join(signature).encode(
            "utf-8", errors="ignore")).hexdigest()
        return signature, fingerprint

    def classify_bug_priority(self, signature, result):
        if result.status in ["crash"]:
            return "reliability"

        if not signature:
            if result.timed_out:
                return "performance"
            return "bonus"

        bug_type, exception_type, message, _, _ = signature
        text = f"{bug_type} {exception_type} {message}".lower()

        # Trust the extracted bug type first to avoid downgrading validity ParseException.
        if bug_type == "validity":
            return "validity"
        if bug_type == "invalidity":
            return "invalidity"
        if bug_type == "functional":
            return "functional"

        if any(k in text for k in ["segfault", "access violation", "fatal"]):
            return "reliability"
        if any(k in text for k in ["functionalbug", "functional bug"]):
            return "functional"
        if any(k in text for k in ["overflow", "out of range", "boundary"]):
            return "boundary"
        if any(k in text for k in ["timeout", "slow", "latency"]):
            return "performance"
        if any(k in text for k in ["invaliditybug", "parseexception"]):
            return "invalidity"
        if any(k in text for k in ["validitybug", "semantic", "incorrect calculation"]):
            return "validity"
        return "bonus"

    def ingest_execution(self, result):
        self.message_counts["run_metrics"] += 1
        self.total_metric_messages += 1
        self.hook_ready = True
        self.hook_target = result.command_display

        text = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        normalized_lines = []
        if text:
            for line in text.splitlines():
                nline = self.normalize_output(line)
                if nline:
                    normalized_lines.append(nline)

        self._track_output_category(text)

        line_counter = Counter(normalized_lines)
        if line_counter:
            self.max_loop_iterations = max(line_counter.values())
            if self.max_loop_iterations > self.best_loop_iterations:
                self.best_loop_iterations = self.max_loop_iterations
                self.loop_iterations_increased = True

        token_hashes = []
        for line in sorted(set(normalized_lines)):
            token = hashlib.sha1(line.encode(
                "utf-8", errors="ignore")).hexdigest()[:16]
            token_hashes.append(token)
            if token not in self.global_coverage:
                self.global_coverage.add(token)
                self.new_block_found = True

        self.path_depth = len(token_hashes)
        if self.path_depth > self.best_path_depth:
            self.best_path_depth = self.path_depth
            self.path_depth_increased = True

        duration_bucket = int(min(result.elapsed_sec * 1000, 60000) // 250)
        feature_raw = "|".join(token_hashes) + \
            f"|ec:{result.exit_code}|tb:{duration_bucket}"
        feature_id = hashlib.sha256(feature_raw.encode(
            "utf-8", errors="ignore")).hexdigest()[:20]

        if feature_id not in self.seen_path_signatures:
            self.seen_path_signatures.add(feature_id)
            self.new_path_signature = True

        if self._last_feature_id is not None:
            edge = f"{self._last_feature_id}->{feature_id}"
            if edge not in self.global_edges:
                self.global_edges.add(edge)
                self.new_edge_found = True
        self._last_feature_id = feature_id

        signature, fingerprint = self.extract_bug_signature(
            text, result.exit_code)
        bug_class = self.classify_bug_priority(signature, result)
        new_bug = False
        if signature and fingerprint:
            self.message_counts["bug_extract"] += 1
            self.total_metric_messages += 1
            self.last_bug_signature = signature
            self.last_bug_fingerprint = fingerprint
            self.last_exception_text = " | ".join(signature)
            if fingerprint not in self.seen_bug_fingerprints:
                self.seen_bug_fingerprints.add(fingerprint)
                new_bug = True

        self.message_counts["feature_extract"] += 1
        self.total_metric_messages += 1

        new_feature = (
            self.new_block_found
            or self.new_edge_found
            or self.new_path_signature
            or self.path_depth_increased
            or self.loop_iterations_increased
        )

        return {
            "new_bug": new_bug,
            "new_feature": new_feature,
            "feature_id": feature_id,
            "bug_signature": signature,
            "bug_class": bug_class,
        }


class ExecutionResult:
    def __init__(
        self,
        status,
        stdout,
        stderr,
        exit_code,
        elapsed_sec,
        rss_delta_kb,
        timed_out,
        command_display,
    ):
        self.status = status
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.elapsed_sec = elapsed_sec
        self.rss_delta_kb = rss_delta_kb
        self.timed_out = timed_out
        self.command_display = command_display


def _worker_exec_loop(binary_path, input_arg, timeout_sec, work_dir, in_q, out_q):
    while True:
        job = in_q.get()
        if job is None:
            break

        job_id, input_text = job
        cmd = [binary_path, input_arg, input_text]
        cmd_display = " ".join(cmd)
        start = time.time()

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                cwd=work_dir,
            )
            elapsed = time.time() - start
            out_q.put(
                {
                    "job_id": job_id,
                    "status": "success",
                    "stdout": completed.stdout,
                    "stderr": completed.stderr,
                    "exit_code": completed.returncode,
                    "elapsed_sec": elapsed,
                    "rss_delta_kb": 0,
                    "timed_out": False,
                    "command_display": cmd_display,
                }
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = time.time() - start
            out_q.put(
                {
                    "job_id": job_id,
                    "status": "hang",
                    "stdout": exc.stdout or "",
                    "stderr": exc.stderr or "",
                    "exit_code": -1,
                    "elapsed_sec": elapsed,
                    "rss_delta_kb": 0,
                    "timed_out": True,
                    "command_display": cmd_display,
                }
            )
        except Exception as exc:
            elapsed = time.time() - start
            out_q.put(
                {
                    "job_id": job_id,
                    "status": "error",
                    "stdout": "",
                    "stderr": str(exc),
                    "exit_code": -2,
                    "elapsed_sec": elapsed,
                    "rss_delta_kb": 0,
                    "timed_out": False,
                    "command_display": cmd_display,
                }
            )


def _result_from_payload(payload):
    return ExecutionResult(
        status=payload["status"],
        stdout=payload["stdout"],
        stderr=payload["stderr"],
        exit_code=payload["exit_code"],
        elapsed_sec=payload["elapsed_sec"],
        rss_delta_kb=payload["rss_delta_kb"],
        timed_out=payload["timed_out"],
        command_display=payload["command_display"],
    )


class CLITargetExecutor:
    def __init__(self, binary_path, input_arg, timeout_sec, work_dir):
        self.binary_path = binary_path
        self.input_arg = input_arg
        self.timeout_sec = timeout_sec
        self.work_dir = work_dir

    def run_one(self, data):
        input_text = data.decode("utf-8", errors="ignore")
        if not input_text:
            input_text = "0"

        cmd = [self.binary_path, self.input_arg, input_text]
        cmd_display = " ".join(cmd)
        start = time.time()

        proc = psutil.Process(os.getpid())
        mem_before = int(proc.memory_info().rss / 1024)

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_sec,
                cwd=self.work_dir,
            )
            elapsed = time.time() - start
            mem_after = int(proc.memory_info().rss / 1024)
            rss_delta = max(0, mem_after - mem_before)
            return ExecutionResult(
                status="success",
                stdout=completed.stdout,
                stderr=completed.stderr,
                exit_code=completed.returncode,
                elapsed_sec=elapsed,
                rss_delta_kb=rss_delta,
                timed_out=False,
                command_display=cmd_display,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = time.time() - start
            mem_after = int(proc.memory_info().rss / 1024)
            rss_delta = max(0, mem_after - mem_before)
            out = exc.stdout or ""
            err = exc.stderr or ""
            return ExecutionResult(
                status="hang",
                stdout=out,
                stderr=err,
                exit_code=-1,
                elapsed_sec=elapsed,
                rss_delta_kb=rss_delta,
                timed_out=True,
                command_display=cmd_display,
            )
        except Exception as exc:
            elapsed = time.time() - start
            mem_after = int(proc.memory_info().rss / 1024)
            rss_delta = max(0, mem_after - mem_before)
            return ExecutionResult(
                status="error",
                stdout="",
                stderr=str(exc),
                exit_code=-2,
                elapsed_sec=elapsed,
                rss_delta_kb=rss_delta,
                timed_out=False,
                command_display=cmd_display,
            )


class PersistentWorkerPoolExecutor:
    def __init__(self, binary_path, input_arg, timeout_sec, work_dir, worker_count=2):
        self.binary_path = binary_path
        self.input_arg = input_arg
        self.timeout_sec = timeout_sec
        self.work_dir = work_dir
        self.worker_count = max(1, int(worker_count))

        self.in_q = mp.Queue(maxsize=max(64, self.worker_count * 8))
        self.out_q = mp.Queue(maxsize=max(64, self.worker_count * 8))
        self.workers = []
        self.next_job_id = 0

        for _ in range(self.worker_count):
            proc = mp.Process(
                target=_worker_exec_loop,
                args=(
                    self.binary_path,
                    self.input_arg,
                    self.timeout_sec,
                    self.work_dir,
                    self.in_q,
                    self.out_q,
                ),
                daemon=True,
            )
            proc.start()
            self.workers.append(proc)

    def submit(self, data):
        input_text = data.decode("utf-8", errors="ignore")
        if not input_text:
            input_text = "0"
        job_id = self.next_job_id
        self.next_job_id += 1
        self.in_q.put((job_id, input_text))
        return job_id

    def get_next_result(self, timeout_sec=None):
        payload = self.out_q.get(timeout=timeout_sec)
        return payload["job_id"], _result_from_payload(payload)

    def run_one(self, data):
        job_id = self.submit(data)
        while True:
            got_job_id, result = self.get_next_result(
                timeout_sec=self.timeout_sec + 1.0)
            if got_job_id == job_id:
                return result

    def shutdown(self):
        # Avoid blocking on queue operations during teardown; terminate workers directly.
        for proc in self.workers:
            try:
                if proc.is_alive():
                    proc.terminate()
                proc.join(timeout=1.0)
            except Exception:
                pass


def is_tier1(result, feedback, tracker):
    if result.status in ["crash"]:
        return True
    if feedback.get("new_bug"):
        return True
    text = (tracker.last_exception_text or "").lower()
    fatal_tokens = ["fatal", "access violation", "segfault", "crash"]
    return any(tok in text for tok in fatal_tokens)


def check_interesting(result, mem_spike, tracker, feedback, stats):
    # Tier 1: bug discovery and triage
    if is_tier1(result, feedback, tracker):
        bug_class = feedback.get("bug_class", "bonus")
        if bug_class == "invalidity":
            return True, "tier_3", "bug:invalidity"
        if bug_class in {"reliability", "functional", "boundary", "performance", "validity"}:
            return True, "tier_1", f"bug:{bug_class}"
        return True, "tier_2", f"bug:{bug_class}"

    # Ignore infrastructure/runtime failures.
    if result.status == "error":
        return False, None, None

    # Treat hangs as non-interesting by default on slow machines.
    # Keep only concrete bug signatures as interesting (handled by tier-1 path above).
    if result.status == "hang" and not feedback.get("new_bug"):
        return False, None, None

    # Tier 2: exploration progress and novel behavior.
    if tracker.new_block_found:
        return True, "tier_2", "new_coverage"
    if tracker.new_edge_found:
        return True, "tier_2", "new_edge"
    if tracker.new_path_signature:
        return True, "tier_2", "new_path_signature"
    if tracker.path_depth_increased:
        return True, "tier_2", "increased_path_depth"
    if tracker.loop_iterations_increased:
        return True, "tier_2", "increased_loop_iterations"
    if feedback.get("new_feature"):
        return True, "tier_2", "new_pseudo_feature"

    # Tier 3: anomalies and fresh output categories.
    if stats.is_exec_outlier(result.elapsed_sec):
        return True, "tier_3", "exec_time_outlier"
    if mem_spike:
        return True, "tier_3", "memory_spike"
    if tracker.new_output_category:
        return True, "tier_3", f"new_output_category:{tracker.last_output_category}"

    return False, None, None


BUG_PRIORITY_REWARD = {
    "reliability": 8.0,
    "functional": 6.0,
    "boundary": 5.0,
    "performance": 4.0,
    "validity": 4.0,
    "bonus": 2.0,
    "invalidity": 0.5,
}


def mutation_reward(tier, reason):
    if reason and reason.startswith("bug:"):
        bug_class = reason.split(":", 1)[1]
        return BUG_PRIORITY_REWARD.get(bug_class, 2.0)

    if tier == "tier_1":
        return 5.0
    if tier == "tier_2":
        return 3.0
    if tier == "tier_3":
        return 1.0
    return 0.0


def clamp_input_size(data, max_input_bytes):
    if max_input_bytes <= 0:
        return data
    if len(data) <= max_input_bytes:
        return data
    start = random.randint(0, len(data) - max_input_bytes)
    return data[start:start + max_input_bytes]


def _decode_input_for_log(data):
    text = data.decode("utf-8", errors="replace")
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    return text


BUG_REPRO_LEDGER_PATH = os.path.join("logs", "bug_repro_ledger.csv")
_seen_repro_entries = set()
BUG_COUNTS_PATH = os.path.join("logs", "bug_counts.csv")
_BUG_COUNTS_INDEX = {}
_BUG_COUNTS_MTIME = None


def _normalize_line_no_for_match(value):
    text = str(value or "").strip()
    if text.endswith(".0"):
        return text[:-2]
    return text


def _normalize_exception_type_for_match(value):
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if "." in text:
        text = text.split(".")[-1]
    return text


def _normalize_file_name_for_match(value):
    return str(value or "").strip().replace("\\", "/").lower()


def _refresh_bug_counts_index():
    global _BUG_COUNTS_INDEX, _BUG_COUNTS_MTIME

    if not os.path.exists(BUG_COUNTS_PATH):
        _BUG_COUNTS_INDEX = {}
        _BUG_COUNTS_MTIME = None
        return

    try:
        mtime = os.path.getmtime(BUG_COUNTS_PATH)
    except Exception:
        _BUG_COUNTS_INDEX = {}
        _BUG_COUNTS_MTIME = None
        return

    if _BUG_COUNTS_MTIME == mtime:
        return

    index = {}
    try:
        with open(BUG_COUNTS_PATH, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                bug_type = str(row.get("bug_type") or "").strip().lower()
                if bug_type not in {"validity", "invalidity", "functional", "parse"}:
                    continue

                exc_type = _normalize_exception_type_for_match(
                    row.get("exc_type") or row.get("exception") or ""
                )
                message = str(row.get("exc_message")
                              or row.get("message") or "").strip()
                file_name = _normalize_file_name_for_match(
                    row.get("filename") or row.get("file") or ""
                )
                line_no = _normalize_line_no_for_match(
                    row.get("lineno") or row.get("line") or "")
                if not exc_type or not message:
                    continue

                key = (exc_type, message, file_name, line_no)

                raw_count = str(row.get("count") or "0").strip()
                try:
                    count = int(float(raw_count))
                except Exception:
                    count = 0

                previous = index.get(key)
                if previous is None:
                    index[key] = (bug_type, count)
                else:
                    prev_type, prev_count = previous
                    # If both labels appear for the same ParseException bucket,
                    # prefer validity to avoid losing semantic-validity signals.
                    if bug_type == "validity" and prev_type != "validity":
                        index[key] = (bug_type, count)
                    elif bug_type == prev_type and count >= prev_count:
                        index[key] = (bug_type, count)
                    elif prev_type != "validity" and count >= prev_count:
                        index[key] = (bug_type, count)
    except Exception:
        index = {}

    _BUG_COUNTS_INDEX = {k: v[0] for k, v in index.items()}
    _BUG_COUNTS_MTIME = mtime


def _lookup_bug_type_from_bug_counts(exception_type, message, file_name, line_no):
    exc_type = _normalize_exception_type_for_match(exception_type)
    if exc_type != "parseexception":
        return ""

    _refresh_bug_counts_index()
    key = (
        exc_type,
        (message or "").strip(),
        _normalize_file_name_for_match(file_name),
        _normalize_line_no_for_match(line_no),
    )
    exact = _BUG_COUNTS_INDEX.get(key, "")
    if exact:
        return exact

    # Fallback when traceback file path or line formatting differs.
    msg = (message or "").strip()
    fallback = ""
    for (k_exc, k_msg, _k_file, _k_line), k_type in _BUG_COUNTS_INDEX.items():
        if k_exc == exc_type and k_msg == msg:
            if k_type == "validity":
                return "validity"
            if not fallback:
                fallback = k_type
    return fallback


def _normalize_path_for_log(path):
    return path.replace("\\", "/")


def _extract_signature_fields(bug_signature):
    bug_type = ""
    exception_type = ""
    message = ""
    file_name = ""
    line_no = ""
    if bug_signature:
        bug_type = str(bug_signature[0]) if len(bug_signature) > 0 else ""
        exception_type = str(bug_signature[1]) if len(
            bug_signature) > 1 else ""
        message = str(bug_signature[2]) if len(bug_signature) > 2 else ""
        file_name = str(bug_signature[3]) if len(bug_signature) > 3 else ""
        line_no = str(bug_signature[4]) if len(bug_signature) > 4 else ""
    return bug_type, exception_type, message, file_name, line_no


def _reclassify_signature_from_bug_counts(bug_signature):
    if not bug_signature:
        return bug_signature

    bug_type, exception_type, message, file_name, line_no = _extract_signature_fields(
        bug_signature)
    if not exception_type:
        return bug_signature

    counts_hint = _lookup_bug_type_from_bug_counts(
        exception_type,
        message,
        file_name,
        line_no,
    )
    if not counts_hint or counts_hint == bug_type:
        return bug_signature

    return (counts_hint, exception_type, message, file_name, line_no)


def _append_bug_repro_ledger(data_hash, input_bytes, bug_signature, reason, json_path, bin_path, result, timestamp):
    os.makedirs("logs", exist_ok=True)
    file_exists = os.path.exists(BUG_REPRO_LEDGER_PATH)
    json_ref = _normalize_path_for_log(json_path)

    # Keep one row per crash artifact for clean triage.
    if json_ref in _seen_repro_entries:
        return
    _seen_repro_entries.add(json_ref)

    bug_signature = _reclassify_signature_from_bug_counts(bug_signature)
    bug_type, exception_type, message, file_name, line_no = _extract_signature_fields(
        bug_signature)
    input_b64 = base64.b64encode(input_bytes).decode(
        "ascii") if input_bytes is not None else ""

    with open(BUG_REPRO_LEDGER_PATH, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "timestamp",
                "category",
                "bug_type",
                "exception",
                "message",
                "file",
                "line",
                "status",
                "exit_code",
                "timed_out",
                "elapsed_sec",
                "command",
                "reason",
                "input_hash",
                "input_text",
                "input_b64",
                "crash_json",
                "crash_bin",
            ])

        writer.writerow([
            timestamp,
            os.path.basename(json_ref).replace(".json", ""),
            bug_type,
            exception_type,
            message,
            file_name,
            line_no,
            result.status,
            result.exit_code,
            result.timed_out,
            f"{result.elapsed_sec:.6f}",
            result.command_display,
            reason,
            data_hash,
            _decode_input_for_log(input_bytes),
            input_b64,
            json_ref,
            _normalize_path_for_log(bin_path),
        ])


class _LedgerResultView:
    def __init__(self, metadata):
        self.status = metadata.get("status", "")
        self.exit_code = metadata.get("exit_code", "")
        self.timed_out = metadata.get("timed_out", False)
        self.elapsed_sec = metadata.get("elapsed_sec", 0.0)
        self.command_display = metadata.get("command", "")


def rebuild_bug_repro_ledger_from_crashes(crashes_dir="crashes"):
    _seen_repro_entries.clear()

    if os.path.exists(BUG_REPRO_LEDGER_PATH):
        os.remove(BUG_REPRO_LEDGER_PATH)

    if not os.path.isdir(crashes_dir):
        return

    for name in sorted(os.listdir(crashes_dir)):
        if not name.endswith(".json"):
            continue

        json_path = os.path.join(crashes_dir, name)
        bin_path = os.path.join(crashes_dir, name[:-5] + ".bin")

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)
        except Exception:
            continue

        input_bytes = b""
        if os.path.exists(bin_path):
            try:
                with open(bin_path, "rb") as f:
                    input_bytes = f.read()
            except Exception:
                input_bytes = b""

        data_hash = hashlib.md5(input_bytes).hexdigest() if input_bytes else ""
        bug_signature = metadata.get("bug_signature")
        reason = metadata.get("reason", "")
        timestamp = int(metadata.get("timestamp", int(time.time())))

        _append_bug_repro_ledger(
            data_hash,
            input_bytes,
            bug_signature,
            reason,
            json_path,
            bin_path,
            _LedgerResultView(metadata),
            timestamp,
        )


def save_crash(data, category, bug_signature, result, reason):
    os.makedirs("crashes", exist_ok=True)
    data_hash = hashlib.md5(data).hexdigest()
    base = f"{category}_{data_hash}"
    bin_path = os.path.join("crashes", f"{base}.bin")
    json_path = os.path.join("crashes", f"{base}.json")

    if not os.path.exists(bin_path):
        with open(bin_path, "wb") as f:
            f.write(data)

    metadata = {
        "category": category,
        "reason": reason,
        "bug_signature": bug_signature,
        "status": result.status,
        "exit_code": result.exit_code,
        "elapsed_sec": result.elapsed_sec,
        "timed_out": result.timed_out,
        "command": result.command_display,
        "timestamp": int(time.time()),
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    _append_bug_repro_ledger(data_hash, data, bug_signature,
                             reason, json_path, bin_path, result, metadata["timestamp"])

    print(f"[!] {category.upper()} saved.")


def clear_binary_owned_logs(logs_dir="logs"):
    os.makedirs(logs_dir, exist_ok=True)
    bug_csv_path = os.path.join(logs_dir, "bug_counts.csv")

    # Preserve existing bug_counts history across runs.
    # Only initialize the file when it does not exist yet.
    if not os.path.exists(bug_csv_path):
        with open(bug_csv_path, "w", encoding="utf-8") as f:
            f.write("bug_type,exception,message,file,line,count\n")


class BlackboxCampaignDashboard:
    def __init__(
        self,
        target_path,
        worker_mode,
        worker_count,
        inflight_jobs,
        timeout_sec,
        max_input_bytes,
        auto_tune_enabled,
    ):
        self.target_name = os.path.basename(target_path)
        self.worker_mode = worker_mode
        self.worker_count = worker_count
        self.inflight_jobs = inflight_jobs
        self.timeout_sec = timeout_sec
        self.max_input_bytes = max_input_bytes
        self.auto_tune_enabled = auto_tune_enabled
        self.iterations = 0
        self.start_time = time.time()
        self.total_bug_hits = 0
        self.unique_bug_count = 0
        self.unique_bug_fingerprints = set()
        self.tier_hits = {"tier_1": 0, "tier_2": 0, "tier_3": 0}
        self.category_hits = {}

    def show(self, tracker, scheduler):
        os.system("cls" if os.name == "nt" else "clear")
        elapsed = time.time() - self.start_time
        speed = self.iterations / elapsed if elapsed > 0 else 0
        bug_density = (self.total_bug_hits / self.iterations *
                       100) if self.iterations > 0 else 0

        print("=" * 50)
        print(f" CLI BLACKBOX FUZZER  {self.target_name}")
        print("=" * 50)
        print(
            f" Iterations: {self.iterations:<10} | Speed: {speed:.2f} exec/s")
        print(
            f" Bug Hits: {self.total_bug_hits:<11} | Unique Bugs: {self.unique_bug_count}")
        print(f" Hit Rate: {bug_density:.2f}%")
        print(
            f" FeatureBlocks: {len(tracker.global_coverage):<7} | FeatureEdges: {len(tracker.global_edges)}")
        print(
            f" FeatureDepth: {tracker.best_path_depth:<8} | RepeatMax: {tracker.best_loop_iterations}")
        print(
            f" RunnerReady: {tracker.hook_ready!s:<8} | SignalMsg: {tracker.total_metric_messages}")
        print(
            f" WorkerMode: {self.worker_mode:<9} | Workers: {self.worker_count}")
        print(
            f" Inflight: {self.inflight_jobs:<11} | Timeout: {self.timeout_sec:.3f}s")
        print(
            f" AutoTune: {self.auto_tune_enabled!s:<10} | MaxInput: {self.max_input_bytes}")
        print(
            f" Tier1: {self.tier_hits['tier_1']:<4} Tier2: {self.tier_hits['tier_2']:<4} Tier3: {self.tier_hits['tier_3']:<4}"
        )
        print(f" MOPT UpdateEvery: {scheduler.update_interval:<4} selections")
        print("-" * 50)
        for i, op in enumerate(scheduler.operators):
            print(f"  {op.__name__:<18}: {scheduler.probabilities[i]:.6f}")
        print("=" * 50)


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="CLI-only fuzzer with MOPT scheduling.")
    parser.add_argument(
        "--target", default="./win-ipv4-parser.exe", help="Target binary path")
    parser.add_argument("--input-arg", default="--ipstr",
                        help="Target input argument name")
    parser.add_argument(
        "--corpus-dir",
        default="corpus/networking/valid_ipv4",
        help="Corpus directory",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--timeout", type=float, default=None,
                        help="Execution timeout in seconds (auto-tuned when omitted)")
    parser.add_argument(
        "--worker-mode",
        choices=["sync", "persistent"],
        default="persistent",
        help="Execution mode: synchronous subprocess or persistent worker pool",
    )
    parser.add_argument("--worker-count", type=int, default=None,
                        help="Worker process count for persistent mode (auto-tuned when omitted)")
    parser.add_argument("--inflight-jobs", type=int, default=None,
                        help="Max in-flight jobs for persistent mode (auto-tuned when omitted)")
    parser.add_argument("--max-input-bytes", type=int, default=None,
                        help="Clamp mutated input size (auto-tuned when omitted)")
    parser.add_argument("--binary-owns-logs", action="store_true", default=True,
                        help="Treat bug_counts.csv and traceback.log as binary-owned outputs")
    parser.add_argument("--fuzzer-owns-logs", dest="binary_owns_logs",
                        action="store_false", help="Allow fuzzer-managed logs (not recommended)")
    parser.add_argument("--auto-tune", dest="auto_tune", action="store_true",
                        default=True, help="Enable startup auto-tuning for runner settings")
    parser.add_argument("--no-auto-tune", dest="auto_tune",
                        action="store_false", help="Disable startup auto-tuning")
    parser.add_argument("--mopt-update-interval", type=int, default=10,
                        help="Selections between MOPT probability updates")
    parser.add_argument("--dashboard-interval", type=int,
                        default=10, help="Dashboard refresh interval")
    parser.add_argument("--iterations", type=int,
                        default=0, help="0 means run forever")
    parser.add_argument("--max-corpus-size", type=int,
                        default=2000, help="Max in-memory corpus size")
    return parser


def generate_candidate(loader, scheduler, max_input_bytes):
    seed = loader.get_random_seed()
    op, op_idx = scheduler.select_operator()

    if op == mut_splice:
        mutated_input = op(seed, loader.get_random_seed())
    else:
        mutated_input = op(seed)

    mutated_input = clamp_input_size(mutated_input, max_input_bytes)
    return op_idx, mutated_input


def auto_tune_runtime(args):
    # Conservative defaults when auto-tune is disabled.
    default_timeout = 3.0
    default_max_input = 96
    default_workers = 2
    default_inflight = 4

    cpu_logical = psutil.cpu_count(logical=True) or os.cpu_count() or 4
    cpu_physical = psutil.cpu_count(logical=False) or max(1, cpu_logical // 2)

    log_friendly_timeout = 5.0 if args.binary_owns_logs else 3.0

    if not args.auto_tune:
        timeout_sec = args.timeout if args.timeout is not None else default_timeout
        max_input_bytes = args.max_input_bytes if args.max_input_bytes is not None else default_max_input
        if args.worker_mode == "sync":
            worker_count = 1
            inflight_jobs = 1
        else:
            worker_count = args.worker_count if args.worker_count is not None else default_workers
            inflight_jobs = args.inflight_jobs if args.inflight_jobs is not None else default_inflight
        if args.timeout is None and args.binary_owns_logs:
            timeout_sec = log_friendly_timeout

        if args.binary_owns_logs and args.worker_mode == "persistent":
            # Avoid log-file races when the target binary writes shared log paths.
            worker_count = 1
            inflight_jobs = 1
        return timeout_sec, worker_count, inflight_jobs, max_input_bytes

    # Auto-tuned settings.
    if args.worker_mode == "sync":
        worker_count = 1
        inflight_jobs = 1
        timeout_sec = args.timeout if args.timeout is not None else (
            log_friendly_timeout if args.binary_owns_logs else (3.0 if cpu_logical >= 8 else 4.0))
        max_input_bytes = args.max_input_bytes if args.max_input_bytes is not None else 80
    else:
        worker_count = args.worker_count if args.worker_count is not None else max(
            2, min(8, cpu_physical))
        inflight_jobs = args.inflight_jobs if args.inflight_jobs is not None else max(
            4, worker_count * 2)
        timeout_sec = args.timeout if args.timeout is not None else (
            log_friendly_timeout if args.binary_owns_logs else (3.0 if cpu_logical >= 8 else 4.0))
        max_input_bytes = args.max_input_bytes if args.max_input_bytes is not None else 96

    if args.binary_owns_logs and args.worker_mode == "persistent":
        # Keep log outputs meaningful and deterministic under binary ownership.
        worker_count = 1
        inflight_jobs = 1

    return timeout_sec, worker_count, inflight_jobs, max_input_bytes


def main():
    args = build_arg_parser().parse_args()
    work_dir = os.getcwd()

    timeout_sec, worker_count, inflight_jobs, max_input_bytes = auto_tune_runtime(
        args)

    set_reproducibility(args.seed)
    if args.binary_owns_logs:
        clear_binary_owned_logs("logs")
    rebuild_bug_repro_ledger_from_crashes("crashes")
    loader = CorpusLoader(args.corpus_dir)
    scheduler = MOPT_Scheduler(
        operators, update_interval=args.mopt_update_interval)
    tracker = CoverageTracker()
    dashboard = BlackboxCampaignDashboard(
        args.target,
        args.worker_mode,
        worker_count,
        inflight_jobs,
        timeout_sec,
        max_input_bytes,
        args.auto_tune,
    )
    stats = PerformanceStats()
    if args.worker_mode == "persistent":
        executor = PersistentWorkerPoolExecutor(
            args.target,
            args.input_arg,
            timeout_sec,
            work_dir,
            worker_count=worker_count,
        )
        inflight_limit = max(1, inflight_jobs)
        persistent_mode = True
    else:
        executor = CLITargetExecutor(
            args.target, args.input_arg, timeout_sec, work_dir)
        inflight_limit = 1
        persistent_mode = False

    iteration_limit = args.iterations
    submitted = 0
    completed = 0
    inflight = {}
    worker_restarts = 0
    max_worker_restarts = 3
    consecutive_result_wait_timeouts = 0
    max_result_wait_timeouts = 5

    try:
        # Execute initial seeds once before mutation to preserve boundary/valid baselines.
        warmup_seeds = list(loader.seeds)
        warmup_limit = len(warmup_seeds)
        if iteration_limit > 0:
            warmup_limit = min(warmup_limit, iteration_limit)

        if warmup_limit > 0:
            print(
                f"[*] Seed warmup: running {warmup_limit} initial corpus inputs once.")

        # Warmup is intentionally synchronous to avoid queue timeout edge cases
        # from persistent workers while establishing baseline seed behavior.
        warmup_executor = CLITargetExecutor(
            args.target,
            args.input_arg,
            timeout_sec,
            work_dir,
        )

        for seed_input in warmup_seeds[:warmup_limit]:
            result = warmup_executor.run_one(seed_input)

            tracker.start_iteration()
            feedback = tracker.ingest_execution(result)
            mem_spike = stats.is_memory_spike(result.rss_delta_kb)

            is_interesting, tier, reason = check_interesting(
                result, mem_spike, tracker, feedback, stats)

            if is_interesting:
                dashboard.tier_hits[tier] += 1
                if reason:
                    dashboard.category_hits[reason] = dashboard.category_hits.get(
                        reason, 0) + 1

                if reason and reason.startswith("bug:"):
                    dashboard.total_bug_hits += 1
                    fingerprint = tracker.last_bug_fingerprint or hashlib.sha256(
                        (tracker.last_exception_text or "unknown").encode(
                            "utf-8", errors="ignore")
                    ).hexdigest()
                    dedup_fingerprint = fingerprint
                    bug_type = ""
                    if tracker.last_bug_signature and len(tracker.last_bug_signature) > 0:
                        bug_type = str(tracker.last_bug_signature[0]).lower()

                    # Keep stricter dedup only for inv/val families; preserve per-input uniqueness for others.
                    if bug_type not in ("invalidity", "validity"):
                        input_hash = hashlib.md5(seed_input).hexdigest()
                        dedup_fingerprint = hashlib.sha256(
                            f"{fingerprint}||{input_hash}".encode(
                                "utf-8", errors="ignore")
                        ).hexdigest()

                    is_new_bug = dedup_fingerprint not in dashboard.unique_bug_fingerprints
                    if is_new_bug:
                        dashboard.unique_bug_fingerprints.add(
                            dedup_fingerprint)
                        dashboard.unique_bug_count += 1
                        category = tracker.last_output_category
                        if category == "none":
                            category = "fatal_system_crash"
                        save_crash(
                            seed_input,
                            f"{category}_u{dashboard.unique_bug_count}",
                            tracker.last_bug_signature,
                            result,
                            reason,
                        )

            submitted += 1
            completed += 1
            dashboard.iterations = completed
            if dashboard.iterations % max(1, args.dashboard_interval) == 0:
                dashboard.show(tracker, scheduler)

        while True:
            if iteration_limit > 0 and submitted >= iteration_limit and not inflight:
                break

            while (
                (iteration_limit == 0 or submitted < iteration_limit)
                and len(inflight) < inflight_limit
            ):
                op_idx, mutated_input = generate_candidate(
                    loader, scheduler, max_input_bytes)
                if persistent_mode:
                    job_id = executor.submit(mutated_input)
                    inflight[job_id] = (op_idx, mutated_input)
                else:
                    result = executor.run_one(mutated_input)
                    inflight[submitted] = (op_idx, mutated_input, result)
                submitted += 1

            if not inflight:
                continue

            if persistent_mode:
                try:
                    done_job_id, result = executor.get_next_result(
                        timeout_sec=max(1.0, timeout_sec * 2.0))
                    consecutive_result_wait_timeouts = 0
                except queue.Empty:
                    # Slow targets can legitimately be late; avoid premature worker restarts.
                    consecutive_result_wait_timeouts += 1
                    dashboard.category_hits["result_wait_timeout"] = dashboard.category_hits.get(
                        "result_wait_timeout", 0) + 1

                    if consecutive_result_wait_timeouts <= max_result_wait_timeouts:
                        continue

                    worker_restarts += 1
                    consecutive_result_wait_timeouts = 0
                    dashboard.category_hits["worker_recovery"] = dashboard.category_hits.get(
                        "worker_recovery", 0) + 1

                    if hasattr(executor, "shutdown"):
                        executor.shutdown()

                    if worker_restarts > max_worker_restarts:
                        # Fall back to sync mode to keep campaign alive.
                        persistent_mode = False
                        executor = CLITargetExecutor(
                            args.target, args.input_arg, timeout_sec, work_dir)
                        inflight_limit = 1
                        inflight.clear()
                        continue

                    # Restart worker pool and requeue in-flight jobs.
                    executor = PersistentWorkerPoolExecutor(
                        args.target,
                        args.input_arg,
                        timeout_sec,
                        work_dir,
                        worker_count=worker_count,
                    )
                    pending = list(inflight.values())
                    inflight.clear()
                    for pending_op_idx, pending_input in pending:
                        job_id = executor.submit(pending_input)
                        inflight[job_id] = (pending_op_idx, pending_input)
                    continue
                except Exception:
                    # Worker queue timeout/crash recovery path.
                    worker_restarts += 1
                    dashboard.category_hits["worker_recovery"] = dashboard.category_hits.get(
                        "worker_recovery", 0) + 1

                    if hasattr(executor, "shutdown"):
                        executor.shutdown()

                    if worker_restarts > max_worker_restarts:
                        # Fall back to sync mode to keep campaign alive.
                        persistent_mode = False
                        executor = CLITargetExecutor(
                            args.target, args.input_arg, timeout_sec, work_dir)
                        inflight_limit = 1
                        inflight.clear()
                        continue

                    # Restart worker pool and requeue in-flight jobs.
                    executor = PersistentWorkerPoolExecutor(
                        args.target,
                        args.input_arg,
                        timeout_sec,
                        work_dir,
                        worker_count=worker_count,
                    )
                    pending = list(inflight.values())
                    inflight.clear()
                    for pending_op_idx, pending_input in pending:
                        job_id = executor.submit(pending_input)
                        inflight[job_id] = (pending_op_idx, pending_input)
                    continue

                if done_job_id not in inflight:
                    # Ignore stale results from previous worker generations.
                    continue

                op_idx, mutated_input = inflight.pop(done_job_id)
            else:
                done_job_id = next(iter(inflight))
                op_idx, mutated_input, result = inflight.pop(done_job_id)

            tracker.start_iteration()
            feedback = tracker.ingest_execution(result)
            mem_spike = stats.is_memory_spike(result.rss_delta_kb)

            is_interesting, tier, reason = check_interesting(
                result, mem_spike, tracker, feedback, stats)

            if is_interesting:
                dashboard.tier_hits[tier] += 1
                if reason:
                    dashboard.category_hits[reason] = dashboard.category_hits.get(
                        reason, 0) + 1

                if reason and reason.startswith("bug:"):
                    dashboard.total_bug_hits += 1
                    fingerprint = tracker.last_bug_fingerprint or hashlib.sha256(
                        (tracker.last_exception_text or "unknown").encode(
                            "utf-8", errors="ignore")
                    ).hexdigest()
                    dedup_fingerprint = fingerprint
                    bug_type = ""
                    if tracker.last_bug_signature and len(tracker.last_bug_signature) > 0:
                        bug_type = str(tracker.last_bug_signature[0]).lower()

                    # Keep stricter dedup only for inv/val families; preserve per-input uniqueness for others.
                    if bug_type not in ("invalidity", "validity"):
                        input_hash = hashlib.md5(mutated_input).hexdigest()
                        dedup_fingerprint = hashlib.sha256(
                            f"{fingerprint}||{input_hash}".encode(
                                "utf-8", errors="ignore")
                        ).hexdigest()

                    is_new_bug = dedup_fingerprint not in dashboard.unique_bug_fingerprints
                    if is_new_bug:
                        dashboard.unique_bug_fingerprints.add(
                            dedup_fingerprint)
                        dashboard.unique_bug_count += 1
                        category = tracker.last_output_category
                        if category == "none":
                            category = "fatal_system_crash"
                        save_crash(
                            mutated_input,
                            f"{category}_u{dashboard.unique_bug_count}",
                            tracker.last_bug_signature,
                            result,
                            reason,
                        )
                else:
                    loader.add_seed(mutated_input, args.max_corpus_size)

                scheduler.update_probabilities(
                    op_idx, mutation_reward(tier, reason))
            else:
                scheduler.update_probabilities(op_idx, 0.0)

            completed += 1
            dashboard.iterations = completed
            if dashboard.iterations % max(1, args.dashboard_interval) == 0:
                dashboard.show(tracker, scheduler)
    finally:
        if hasattr(executor, "shutdown"):
            executor.shutdown()

    dashboard.show(tracker, scheduler)
    print("[*] Fuzzing session complete.")


if __name__ == "__main__":
    main()
