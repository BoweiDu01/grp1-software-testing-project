# aflpp_binary_baseline.py
#
# afl-fuzz -Q -i corpus/networking/cidr_mixed -o out -E 5000 -- \
#   ./.venv/bin/python3 aflpp_binary_baseline.py --driver drivers/cidrize.json
#
# Optional:
#   --report-handled-bugs-to-afl
# If set, handled bugs from bug_counts.csv will also be turned into AFL crashes.
#
# Notes:
# - Use -Q only if your binary is uninstrumented and you want QEMU mode.
# - If the target binary is AFL++-instrumented, drop -Q and run normally.
# - This wrapper preserves your existing CSV schema and bug_counts-based handled bug detection.

# ~/software_testing/AFLplusplus/afl-fuzz -Q \
#   -z \
#   -t 3000 \
#   -i corpus/networking/cidr_mixed \
#   -o out_cidr \
#   -E 5000 \
#   -- \
#   ./.venv/bin/python3 python_afl_binary_baseline.py --driver drivers/cidrize.json

# ~/software_testing/AFLplusplus/afl-fuzz -Q \
#   -z \
#   -t 3000 \
#   -i corpus/networking/ipv4 \
#   -o out_ipv4 \
#   -E 5000 \
#   -- \
#   ./.venv/bin/python3 python_afl_binary_baseline.py \
#     --driver drivers/ipv4_blackbox.json

# ~/software_testing/AFLplusplus/afl-fuzz -Q \
#   -z \
#   -t 3000 \
#   -i corpus/networking/ipv6 \
#   -o out_ipv6 \
#   -E 5000 \
#   -- \
#   ./.venv/bin/python3 python_afl_binary_baseline.py \
#     --driver drivers/ipv6_blackbox.json

# Without QEMU for already instrumented binaries DO NOT PUT -Q

# if want bug to be afl crashes as well
#   --report-handled-bugs-to-afl

import sys
import os
import csv
import time
import json
import base64
import hashlib
import argparse
import signal
import subprocess

LOG_PATH = "logs/aflpp_binary_baseline_5000.csv"
BUG_COUNTS_PATH = "logs/bug_counts.csv"


def load_driver(driver_path: str) -> dict:
    with open(driver_path, "r", encoding="utf-8") as f:
        return json.load(f)


def init_log() -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "input_hash",
                "status",            # success / handled_bug / native_crash
                "afl_reportable",    # true / false
                "exit_code",
                "timed_out",
                "elapsed_sec",
                "command",
                "mutated_text",
                "mutated_b64",
                "bug_type",
                "exception",
                "message",
                "file",
                "line",
                "bug_fingerprint",
            ])


def ensure_bug_counts_exists() -> None:
    os.makedirs("logs", exist_ok=True)
    if not os.path.exists(BUG_COUNTS_PATH):
        with open(BUG_COUNTS_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["bug_type", "exc_type", "exc_message", "filename", "lineno", "count"])


def log_row(row: list) -> None:
    with open(LOG_PATH, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(row)


def decode_for_log(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    return text.replace("\r", "\\r").replace("\n", "\\n")


def classify_bug_type(exc_name: str, message: str) -> str:
    e = (exc_name or "").lower()
    m = (message or "").lower()

    if "timeout" in e or "timeout" in m:
        return "performance"
    if "memory" in e or "memory" in m:
        return "memory"
    if "parse" in e or "syntax" in e:
        return "invalidity"
    if "valueerror" in e or "invalid" in m:
        return "invalidity"
    if "assert" in e:
        return "functional"
    return "exception"


def get_file_state(path: str):
    try:
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size)
    except FileNotFoundError:
        return None


def read_last_bug_count_row():
    if not os.path.exists(BUG_COUNTS_PATH):
        return None

    try:
        with open(BUG_COUNTS_PATH, "r", newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        if not rows:
            return None
        row = rows[-1]
        return {
            "bug_type": str(row.get("bug_type", "")).strip(),
            "exc_type": str(row.get("exc_type", "")).strip(),
            "exc_message": str(row.get("exc_message", "")).strip(),
            "filename": str(row.get("filename", "")).strip(),
            "lineno": str(row.get("lineno", "")).strip(),
            "count": str(row.get("count", "")).strip(),
        }
    except Exception:
        return None


def bug_fingerprint_from_row(row: dict) -> str:
    if not row:
        return ""
    raw = "||".join([
        row.get("bug_type", ""),
        row.get("exc_type", ""),
        row.get("exc_message", ""),
        row.get("filename", ""),
        row.get("lineno", ""),
    ])
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def build_target_argv(driver: dict, fuzz_text: str) -> list[str]:
    argv = [driver["target"]]
    for arg in driver.get("argv", []):
        if arg == "@@":
            argv.append(fuzz_text)
        else:
            argv.append(arg)
    return argv


def build_command_display(argv: list[str]) -> str:
    return " ".join(argv)


def _signal_from_env():
    sig_name = os.getenv("PYTHON_AFL_SIGNAL", "SIGABRT").strip()
    if not sig_name.startswith("SIG"):
        sig_name = "SIG" + sig_name
    return getattr(signal, sig_name, signal.SIGABRT)


def _force_afl_crash() -> None:
    sig = _signal_from_env()
    os.kill(os.getpid(), sig)
    os._exit(128 + int(sig))


def write_log(
    *,
    start_time: float,
    input_hash: str,
    status: str,
    afl_reportable: bool,
    exit_code: int,
    timed_out: str,
    command_display: str,
    mutated_text: str,
    mutated_b64: str,
    bug_type: str,
    exc_name: str,
    message: str,
    file_name: str,
    line_no: str,
    bug_fp: str,
) -> None:
    elapsed = time.time() - start_time
    log_row([
        int(time.time()),
        input_hash,
        status,
        "true" if afl_reportable else "false",
        exit_code,
        timed_out,
        f"{elapsed:.6f}",
        command_display,
        mutated_text,
        mutated_b64,
        bug_type,
        exc_name,
        message,
        file_name,
        line_no,
        bug_fp,
    ])


def detect_handled_bug_from_bug_counts(before_state):
    after_state = get_file_state(BUG_COUNTS_PATH)
    if before_state == after_state:
        return None

    row = read_last_bug_count_row()
    if row is None:
        return None

    return {
        "bug_type": row["bug_type"],
        "exc_name": row["exc_type"],
        "message": row["exc_message"],
        "file_name": row["filename"],
        "line_no": row["lineno"],
        "bug_fingerprint": bug_fingerprint_from_row(row),
    }


def run_target_subprocess(driver: dict, data: bytes):
    input_mode = driver.get("input_mode", "argv")
    timeout_sec = float(driver.get("timeout", 20.0))
    fuzz_text = data.decode("utf-8", errors="ignore")

    if input_mode == "argv":
        argv = build_target_argv(driver, fuzz_text)
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_sec,
            check=False,
        )
        return argv, completed

    elif input_mode == "stdin":
        argv = [driver["target"]] + driver.get("argv", [])
        completed = subprocess.run(
            argv,
            input=data,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_sec,
            check=False,
        )
        return argv, completed

    else:
        raise ValueError(f"Unsupported input_mode: {input_mode}")


def fuzz_one(driver: dict, report_handled_bugs_to_afl: bool) -> None:
    ensure_bug_counts_exists()

    start = time.time()
    data = sys.stdin.buffer.read()

    mutated_text = decode_for_log(data)
    mutated_b64 = base64.b64encode(data).decode("ascii")
    input_hash = hashlib.md5(data).hexdigest()

    status = "success"
    exit_code = 0
    timed_out = "false"
    bug_type = ""
    exc_name = ""
    message = ""
    file_name = ""
    line_no = ""
    command_display = ""
    bug_fp = ""
    afl_reportable = False

    bug_counts_before = get_file_state(BUG_COUNTS_PATH)

    try:
        argv, completed = run_target_subprocess(driver, data)
        command_display = build_command_display(argv)
        exit_code = int(completed.returncode)

        handled = detect_handled_bug_from_bug_counts(bug_counts_before)
        if handled is not None:
            status = "handled_bug"
            exit_code = 0
            bug_type = handled["bug_type"]
            exc_name = handled["exc_name"]
            message = handled["message"]
            file_name = handled["file_name"]
            line_no = handled["line_no"]
            bug_fp = handled["bug_fingerprint"]
            afl_reportable = report_handled_bugs_to_afl

            write_log(
                start_time=start,
                input_hash=input_hash,
                status=status,
                afl_reportable=afl_reportable,
                exit_code=exit_code,
                timed_out=timed_out,
                command_display=command_display,
                mutated_text=mutated_text,
                mutated_b64=mutated_b64,
                bug_type=bug_type,
                exc_name=exc_name,
                message=message,
                file_name=file_name,
                line_no=line_no,
                bug_fp=bug_fp,
            )

            if report_handled_bugs_to_afl:
                _force_afl_crash()
            return

        if exit_code == 0:
            status = "success"
            afl_reportable = False

        else:
            status = "native_crash"
            afl_reportable = True

            if exit_code < 0:
                sig_num = -exit_code
                try:
                    sig_name = signal.Signals(sig_num).name
                except Exception:
                    sig_name = f"signal_{sig_num}"
                exc_name = sig_name
                message = f"terminated by signal {sig_num}"
                bug_type = classify_bug_type(sig_name, message)
            else:
                exc_name = "NonZeroExit"
                message = f"process exited with code {exit_code}"
                bug_type = classify_bug_type(exc_name, message)

            bug_fp = hashlib.sha256(
                f"{bug_type}||{exc_name}||{message}||{file_name}||{line_no}".encode("utf-8", errors="ignore")
            ).hexdigest()

            write_log(
                start_time=start,
                input_hash=input_hash,
                status=status,
                afl_reportable=afl_reportable,
                exit_code=exit_code,
                timed_out=timed_out,
                command_display=command_display,
                mutated_text=mutated_text,
                mutated_b64=mutated_b64,
                bug_type=bug_type,
                exc_name=exc_name,
                message=message,
                file_name=file_name,
                line_no=line_no,
                bug_fp=bug_fp,
            )

            _force_afl_crash()
            return

    except subprocess.TimeoutExpired:
        argv = build_target_argv(driver, data.decode("utf-8", errors="ignore")) \
            if driver.get("input_mode", "argv") == "argv" \
            else [driver["target"]] + driver.get("argv", [])
        command_display = build_command_display(argv)

        status = "native_crash"
        afl_reportable = True
        exit_code = -1
        timed_out = "true"
        bug_type = "performance"
        exc_name = "TimeoutExpired"
        message = f"target exceeded timeout={driver.get('timeout', 20.0)} sec"

        bug_fp = hashlib.sha256(
            f"{bug_type}||{exc_name}||{message}||{file_name}||{line_no}".encode("utf-8", errors="ignore")
        ).hexdigest()

        write_log(
            start_time=start,
            input_hash=input_hash,
            status=status,
            afl_reportable=afl_reportable,
            exit_code=exit_code,
            timed_out=timed_out,
            command_display=command_display,
            mutated_text=mutated_text,
            mutated_b64=mutated_b64,
            bug_type=bug_type,
            exc_name=exc_name,
            message=message,
            file_name=file_name,
            line_no=line_no,
            bug_fp=bug_fp,
        )

        _force_afl_crash()
        return

    except Exception as e:
        argv = build_target_argv(driver, data.decode("utf-8", errors="ignore")) \
            if driver.get("input_mode", "argv") == "argv" \
            else [driver["target"]] + driver.get("argv", [])
        command_display = build_command_display(argv)

        status = "native_crash"
        afl_reportable = True
        exit_code = 1
        bug_type = classify_bug_type(type(e).__name__, str(e))
        exc_name = type(e).__name__
        message = str(e)

        bug_fp = hashlib.sha256(
            f"{bug_type}||{exc_name}||{message}||{file_name}||{line_no}".encode("utf-8", errors="ignore")
        ).hexdigest()

        write_log(
            start_time=start,
            input_hash=input_hash,
            status=status,
            afl_reportable=afl_reportable,
            exit_code=exit_code,
            timed_out=timed_out,
            command_display=command_display,
            mutated_text=mutated_text,
            mutated_b64=mutated_b64,
            bug_type=bug_type,
            exc_name=exc_name,
            message=message,
            file_name=file_name,
            line_no=line_no,
            bug_fp=bug_fp,
        )

        _force_afl_crash()
        return

    else:
        write_log(
            start_time=start,
            input_hash=input_hash,
            status=status,
            afl_reportable=afl_reportable,
            exit_code=exit_code,
            timed_out=timed_out,
            command_display=command_display,
            mutated_text=mutated_text,
            mutated_b64=mutated_b64,
            bug_type=bug_type,
            exc_name=exc_name,
            message=message,
            file_name=file_name,
            line_no=line_no,
            bug_fp=bug_fp,
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver", required=True, help="Path to driver JSON")
    parser.add_argument(
        "--report-handled-bugs-to-afl",
        action="store_true",
        help="Treat handled bugs from bug_counts.csv as AFL crashes too",
    )
    args = parser.parse_args()

    driver = load_driver(args.driver)
    init_log()
    fuzz_one(driver, args.report_handled_bugs_to_afl)
    os._exit(0)


if __name__ == "__main__":
    main()