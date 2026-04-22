# python_afl_baseline.py
#
# Run with:
# py-afl-fuzz -i corpus/serialization/json_valid -o out -n -- \
# ./.venv/bin/python3 python_afl_baseline.py --driver drivers/json_whitebox.json

#DUMB MODE
# py-afl-fuzz -i corpus/serialization/json_valid -o out -n -E 5000 -- \
# ./.venv/bin/python3 python_afl_baseline.py --driver drivers/json_whitebox.json

# py-afl-fuzz -i corpus/serialization/json_valid -o out -E 5000 -- \
# ./.venv/bin/python3 python_afl_baseline.py --driver drivers/json_whitebox.json

# python_afl_baseline.py
#
# Run with:
# py-afl-fuzz -i corpus/serialization/json_valid -o out -E 5000 -- \
# ./.venv/bin/python3 python_afl_baseline.py --driver drivers/json_whitebox.json
#
# Optional:
#   --report-handled-bugs-to-afl
# If set, handled bugs from bug_counts.csv will also be turned into AFL crashes.

# py-afl-fuzz -i corpus/serialization/json_valid -o out -E 5000 -- \
# ./.venv/bin/python3 python_afl_baseline.py --driver drivers/json_whitebox.json --report-handled-bugs-to-afl

import afl
import sys
import os
import csv
import time
import json
import base64
import hashlib
import argparse
import traceback
import runpy
import signal

LOG_PATH = "logs/python_afl_baseline_5000.csv"
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


def build_target_argv(driver: dict, fuzz_text: str) -> list[str]:
    argv = [driver["target"]]
    for arg in driver.get("argv", []):
        if arg == "@@":
            argv.append(fuzz_text)
        else:
            argv.append(arg)
    return argv


def build_command_display(driver: dict, argv: list[str]) -> str:
    interpreter = driver.get("interpreter", "python3")
    return " ".join([interpreter] + argv)


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


def run_target_in_process(driver: dict, data: bytes) -> list[str]:
    """
    Run the Python target in-process so python-afl can instrument it.

    IMPORTANT:
    - Keep cwd at repo root/current working dir so target writes to ./logs
      like your custom fuzzer.
    - Only add target_dir to sys.path for imports.
    """
    target_path = os.path.abspath(driver["target"])
    target_dir = os.path.dirname(target_path)

    fuzz_text = data.decode("utf-8", errors="ignore")
    argv = build_target_argv(driver, fuzz_text)

    old_argv = sys.argv[:]
    old_sys_path = sys.path[:]
    old_cwd = os.getcwd()

    try:
        sys.argv = argv

        if old_cwd not in sys.path:
            sys.path.insert(0, old_cwd)

        if target_dir not in sys.path:
            sys.path.insert(0, target_dir)

        # DO NOT chdir(target_dir)
        runpy.run_path(target_path, run_name="__main__")
        return argv

    finally:
        sys.argv = old_argv
        sys.path[:] = old_sys_path
        os.chdir(old_cwd)


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
        argv = run_target_in_process(driver, data)
        command_display = build_command_display(driver, argv)

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

    except SystemExit as e:
        argv = build_target_argv(driver, data.decode("utf-8", errors="ignore"))
        command_display = build_command_display(driver, argv)

        code = e.code if isinstance(e.code, int) else 1
        exit_code = code

        if code == 0:
            status = "success"
        else:
            status = "native_crash"
            afl_reportable = True
            bug_type = "exception"
            exc_name = "SystemExit"
            message = str(e)

            tb = traceback.extract_tb(e.__traceback__)
            if tb:
                last = tb[-1]
                file_name = last.filename
                line_no = str(last.lineno)

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

        if code != 0:
            _force_afl_crash()
        return

    except Exception as e:
        argv = build_target_argv(driver, data.decode("utf-8", errors="ignore"))
        command_display = build_command_display(driver, argv)

        status = "native_crash"
        afl_reportable = True
        exit_code = 1
        bug_type = classify_bug_type(type(e).__name__, str(e))
        exc_name = type(e).__name__
        message = str(e)

        tb = traceback.extract_tb(e.__traceback__)
        if tb:
            last = tb[-1]
            file_name = last.filename
            line_no = str(last.lineno)

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

    afl.init()
    fuzz_one(driver, args.report_handled_bugs_to_afl)
    os._exit(0)


if __name__ == "__main__":
    main()