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
import re
import io
import contextlib

LOG_PATH = "logs/python_afl_baseline_5000.csv"

TRACEBACK_FRAME_RE = re.compile(
    r'^\s*File "([^"]+)", line (\d+), in ([^\r\n]+)\s*$',
    re.MULTILINE,
)

SUMMARY_PATTERN = re.compile(
    r"\('(\w+)',\s*<class\s*'([^']+)'>,\s*.*?,.*?, (\d+)\)"
)

CUSTOM_BUG_PATTERN = re.compile(
    r"[Aa] (\w+) bug has been triggered: (.*)"
)

PY_EXCEPTION_LINE_RE = re.compile(
    r'(?m)^([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*): (.*)$'
)

GENERIC_FILE_LINE_RE = re.compile(
    r'([A-Za-z0-9_./\\-]+\.[A-Za-z0-9_+-]+):(\d+)'
)

LINE_ONLY_RE = re.compile(
    r'(?i)\bline\s+(\d+)\b'
)


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
                "status",
                "afl_reportable",
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


def log_row(row: list) -> None:
    with open(LOG_PATH, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(row)


def decode_for_log(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    return text.replace("\r", "\\r").replace("\n", "\\n")


def normalize_exception_name(exc_name: str) -> str:
    if not exc_name:
        return "UnknownBug"
    return exc_name.split(".")[-1]


def build_target_argv(driver: dict, fuzz_text: str) -> list[str]:
    argv = [driver["target"]]
    for arg in driver.get("argv", []):
        if arg == "@@":
            argv.append(fuzz_text)
        else:
            argv.append(arg)
    return argv


def build_command_display(driver: dict, argv: list[str]) -> str:
    interpreter = driver.get("interpreter", "")
    if interpreter:
        return " ".join([interpreter] + argv)
    return " ".join(argv)


def extract_traceback_frames(tb_text: str) -> list[tuple[str, str, str]]:
    matches = TRACEBACK_FRAME_RE.findall(tb_text or "")
    return [(file.strip(), line.strip(), func.strip()) for file, line, func in matches]


def extract_bug_location(tb_text: str) -> tuple[str, str]:
    combined = tb_text or ""

    m = SUMMARY_PATTERN.search(combined)
    if m:
        return "", m.group(3).strip()

    frames = extract_traceback_frames(combined)
    if frames:
        file_name, line_no, _ = frames[-1]
        return file_name, line_no

    m = GENERIC_FILE_LINE_RE.search(combined)
    if m:
        return m.group(1).strip(), m.group(2).strip()

    m = LINE_ONLY_RE.search(combined)
    if m:
        return "", m.group(1).strip()

    return "", ""


def classify_bug(stdout_text: str, stderr_text: str) -> tuple[str, str]:
    combined = (stdout_text or "") + "\n" + (stderr_text or "")

    # 1. internal tuple format
    m = SUMMARY_PATTERN.search(combined)
    if m:
        bug_type = m.group(1).strip()
        exc_name = normalize_exception_name(m.group(2).strip())
        return bug_type, exc_name

    # 2. custom marker format
    m = CUSTOM_BUG_PATTERN.search(combined)
    if m:
        bug_type = m.group(1).strip().lower()
        exc_name = m.group(2).strip()
        if len(exc_name) > 50:
            exc_name = exc_name[:50]
        return bug_type, exc_name

    # 3. standard Python exception line
    m = PY_EXCEPTION_LINE_RE.search(combined)
    if m:
        full_exc = m.group(1).strip()
        exc_name = normalize_exception_name(full_exc)
        return "python_exception", exc_name

    # 4. ParseException special case
    if "ParseException" in combined:
        return "invalidity", "ParseException"

    # 5. raw fallback
    fallback = (stderr_text or "").strip()
    if not fallback:
        fallback = (stdout_text or "").strip()
    if fallback:
        fallback = fallback.replace("\n", " ")
        if len(fallback) > 40:
            fallback = fallback[:40]
        return "raw_crash", fallback

    return "unknown", "UnknownBug"


def extract_message(stdout_text: str, stderr_text: str) -> str:
    clean = (stderr_text or "").strip()
    if not clean:
        clean = (stdout_text or "").strip()

    if clean:
        return clean.splitlines()[0][:200]

    return ""


def build_bug_fingerprint(
    bug_type: str,
    exc_name: str,
    file_name: str,
    line_no: str,
) -> str:
    raw = "||".join([
        bug_type or "",
        normalize_exception_name(exc_name),
        file_name or "",
        line_no or "",
    ])
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def run_target_in_process(driver: dict, data: bytes) -> tuple[list[str], str, str]:
    """
    Run the Python target in-process so python-afl can instrument it.

    Returns:
        (argv, captured_stdout, captured_stderr)

    IMPORTANT:
    - Keep cwd at repo root/current working dir.
    - Only add target_dir to sys.path for imports.
    """
    target_path = os.path.abspath(driver["target"])
    target_dir = os.path.dirname(target_path)

    fuzz_text = data.decode("utf-8", errors="ignore")
    argv = build_target_argv(driver, fuzz_text)

    old_argv = sys.argv[:]
    old_sys_path = sys.path[:]
    old_cwd = os.getcwd()

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    try:
        sys.argv = argv

        if old_cwd not in sys.path:
            sys.path.insert(0, old_cwd)

        if target_dir not in sys.path:
            sys.path.insert(0, target_dir)

        with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
            runpy.run_path(target_path, run_name="__main__")

        return argv, stdout_buf.getvalue(), stderr_buf.getvalue()

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
    exception: str,
    message: str,
    file_name: str,
    line_no: str,
    bug_fingerprint: str,
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
        exception,
        message,
        file_name,
        line_no,
        bug_fingerprint,
    ])


def fuzz_one(driver: dict, report_handled_bugs_to_afl: bool) -> None:
    start = time.time()
    data = sys.stdin.buffer.read()

    mutated_text = decode_for_log(data)
    mutated_b64 = base64.b64encode(data).decode("ascii")
    input_hash = hashlib.md5(data).hexdigest()

    status = "success"
    exit_code = 0
    timed_out = "false"
    bug_type = ""
    exception = ""
    message = ""
    file_name = ""
    line_no = ""
    command_display = ""
    bug_fingerprint = ""
    afl_reportable = False

    try:
        argv, captured_stdout, captured_stderr = run_target_in_process(driver, data)
        command_display = build_command_display(driver, argv)

        combined = (captured_stdout or "") + "\n" + (captured_stderr or "")
        has_bug_markers = (
            "Bug Type" in combined or
            "Exception:" in combined or
            "Traceback" in combined or
            "bug has been triggered" in combined.lower()
        )

        if has_bug_markers:
            status = "handled_bug"
            exit_code = 0
            afl_reportable = report_handled_bugs_to_afl

            bug_type, exception = classify_bug(captured_stdout, captured_stderr)
            message = extract_message(captured_stdout, captured_stderr)
            file_name, line_no = extract_bug_location(combined)
            bug_fingerprint = build_bug_fingerprint(bug_type, exception, file_name, line_no)

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
                exception=exception,
                message=message,
                file_name=file_name,
                line_no=line_no,
                bug_fingerprint=bug_fingerprint,
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

            tb_text = traceback.format_exc()
            bug_type, exception = classify_bug("", tb_text)
            message = str(e)[:200]
            file_name, line_no = extract_bug_location(tb_text)
            bug_fingerprint = build_bug_fingerprint(bug_type, exception, file_name, line_no)

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
            exception=exception,
            message=message,
            file_name=file_name,
            line_no=line_no,
            bug_fingerprint=bug_fingerprint,
        )

        if code != 0:
            _force_afl_crash()
        return

    except Exception:
        argv = build_target_argv(driver, data.decode("utf-8", errors="ignore"))
        command_display = build_command_display(driver, argv)

        status = "handled_bug"
        exit_code = 0
        afl_reportable = report_handled_bugs_to_afl

        tb_text = traceback.format_exc()
        bug_type, exception = classify_bug("", tb_text)
        message = extract_message("", tb_text)
        file_name, line_no = extract_bug_location(tb_text)
        bug_fingerprint = build_bug_fingerprint(bug_type, exception, file_name, line_no)

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
            exception=exception,
            message=message,
            file_name=file_name,
            line_no=line_no,
            bug_fingerprint=bug_fingerprint,
        )

        if report_handled_bugs_to_afl:
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
            exception=exception,
            message=message,
            file_name=file_name,
            line_no=line_no,
            bug_fingerprint=bug_fingerprint,
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver", required=True, help="Path to driver JSON")
    parser.add_argument(
        "--report-handled-bugs-to-afl",
        action="store_true",
        help="Treat handled bugs from the current run's traceback as AFL crashes too",
    )
    args = parser.parse_args()

    driver = load_driver(args.driver)
    init_log()

    afl.init()
    fuzz_one(driver, args.report_handled_bugs_to_afl)
    os._exit(0)


if __name__ == "__main__":
    main()