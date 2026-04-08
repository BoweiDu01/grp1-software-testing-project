from collections import defaultdict
from buggy_json import loads
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import pandas as pd
import os
from datetime import datetime,UTC
import traceback
from buggy_json.decoder_stv import PerformanceBug, InvalidityBug, JSONDecodeError
import tempfile
import json
import coverage

def print_full_coverage_summary(cov):
    """
    Prints line, branch, and combined coverage using coverage.py JSON report.
    This mirrors how coverage.py CLI computes totals, but shows them separately.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        json_path = tmp.name

    try:
        cov.json_report(outfile=json_path)

        with open(json_path) as f:
            report = json.load(f)

        totals = report["totals"]

        statements = totals["num_statements"]
        covered_lines = totals["covered_lines"]

        branches = totals.get("num_branches", 0)
        covered_branches = totals.get("covered_branches", 0)

        line_cov = (
            covered_lines / statements * 100
            if statements else 100.0
        )

        branch_cov = (
            covered_branches / branches * 100
            if branches else 100.0
        )

        combined_cov = (
            (covered_lines + covered_branches)
            / (statements + branches)
            * 100
            if (statements + branches) else 100.0
        )

        print("\n" + "=" * 60)
        print("detailed coverage summary")
        print("=" * 60)
        print(f"line coverage     : {line_cov:.2f}% ({covered_lines}/{statements})")
        print(f"branch coverage   : {branch_cov:.2f}% ({covered_branches}/{branches})")
        print(f"combined coverage : {combined_cov:.2f}%")
        print("=" * 60)

    finally:
        os.remove(json_path)

def print_missing_branches(cov):
    print("\n" + "=" * 60)
    print("uncovered branches")
    print("=" * 60)
    data = cov.get_data()
    for filename in sorted(data.measured_files()):
        if "buggy_json" not in filename:
            continue
        try:
            (
                _,
                _statements,
                _excluded,
                _missing_lines,
                missing_branches,
            ) = cov.analysis2(filename)
        except coverage.CoverageException:
            continue
        if not missing_branches:
            continue
        any_missing = True
        print(f"\nfile: {filename}")
        by_line = {}
        print("missing_branches", missing_branches)
        for from_to_line in missing_branches.split(","):
            from_to_line = from_to_line.strip()
            if "-" in from_to_line:  # fixed: check if there's a dash
                from_line, to_line = from_to_line.split("-")
                by_line.setdefault(int(from_line), []).append(int(to_line))
            else:  # fixed: handle branches without a target (exits)
                from_line = from_to_line
                by_line.setdefault(int(from_line), []).append(-1)  # use -1 for exit

        for from_line, targets in sorted(by_line.items()):
            targets_str = ", ".join(
                "exit" if t < 0 else f"line {t}" for t in targets
            )
            print(f" line {from_line}: missing branch to {targets_str}")

def track_exception(exc: Exception):
    tb = exc.__traceback__
    last_frame = traceback.extract_tb(tb)[-1]

    bug_id = (
        type(exc),
        str(exc),
        last_frame.filename,
        last_frame.lineno
    )
    print("=" * 60)
    print("TRACEBACK")
    print("=" * 60)
    traceback.print_exc()
    print("=" * 60)
    
    return bug_id

def log_full_traceback(exc, bug_type, log_dir="logs", filename="tracebacks.log"):
    """
    Appends a full traceback to a log file for later analysis.
    """
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, filename)

    timestamp = datetime.now(UTC)

    with open(log_path, "a") as f:
        f.write("=" * 80 + "\n")
        f.write(f"Timestamp : {timestamp}\n")
        f.write(f"Bug Type  : {bug_type}\n")
        f.write(f"Exception: {type(exc).__name__}: {exc}\n\n")
        f.write("Traceback:\n")
        f.write("".join(traceback.format_exception(exc)))
        f.write("\n\n")

def bug_count_to_csv(bug_count, output_path):
    rows = []

    if not bug_count:
        print("No bugs found. Skipping CSV creation")
        return

    for key, count in bug_count.items():
        bug_type, exc_type, exc_message, filename, lineno = key
        rows.append({
            "bug_type": bug_type,
            "exc_type": exc_type.__name__,
            "exc_message": exc_message,   
            "filename": filename,
            "lineno": lineno,
            "count": count,
        })
    
    new_df = pd.DataFrame(rows)
    
    if os.path.exists(output_path):
        existing_df = pd.read_csv(output_path)
        
        combined_df = pd.concat([existing_df, new_df], ignore_index=True)
        
        combined_df = combined_df.groupby(
            ["bug_type", "exc_type", "exc_message", "filename", "lineno"], 
            as_index=False
        )["count"].sum()
    else:
        combined_df = new_df
    
    if not combined_df.empty:
        combined_df.to_csv(output_path, index=False)

if __name__ == "__main__":
    notes = """
A program to decode JSON.

Decoding JSON::

    >>> import json
    >>> obj = ['foo', {'bar': ['baz', None, 1.0, 2]}]
    >>> json.loads('["foo", {"bar":["baz", null, 1.0, 2]}]') == obj
    True
    >>> json.loads('"\\"foo\\bar"') == '"foo\x08ar'
    True

Specializing JSON object decoding::

    >>> import json
    >>> def as_complex(dct):
    ...     if '__complex__' in dct:
    ...         return complex(dct['real'], dct['imag'])
    ...     return dct
    ...
    >>> json.loads('{"__complex__": true, "real": 1, "imag": 2}',
    ...     object_hook=as_complex)
    (1+2j)
    >>> from decimal import Decimal
    >>> json.loads('1.1', parse_float=Decimal) == Decimal('1.1')
    True


Using json from the shell to validate and pretty-print::

    $ echo '{"json":"obj"}' | python -m json
    {
        "json": "obj"
    }
    $ echo '{ 1.2:3.4}' | python -m json
    Expecting property name enclosed in double quotes: line 1 column 3 (char 2)
    """

    parser = ArgumentParser("JSON-decoder", description=notes, formatter_class=RawDescriptionHelpFormatter)

    parser.add_argument("--str-json", help="Deserialize ``str-json`` (a ``str``, ``bytes`` or ``bytearray`` instance containing a JSON document) to a Python object.")
    parser.add_argument("--coverage-file", help="Path to store coverage data (default: .coverage_buggy_json)", default=".coverage_buggy_json")
    parser.add_argument("--show-coverage", help="Display coverage report after execution", action="store_true")
    parser.add_argument("--reset-coverage", help="Reset coverage data before this run", action="store_true")
    parser.add_argument("--coverage-summary", help="Show only coverage summary without running any function", action="store_true")
    args = parser.parse_args()
    
    bug_count = defaultdict(int)

    cov = coverage.Coverage(
        data_file=args.coverage_file,
        source=['buggy_json'],  
        branch=True  
    )
    
    
    if args.coverage_summary:
        if os.path.exists(args.coverage_file):
            cov.load()
            print("\n" + "="*60)
            print("CUMULATIVE COVERAGE SUMMARY")
            print("="*60)
            cov.report(file=None, show_missing=True)
            print_full_coverage_summary(cov)
            print_missing_branches(cov)
            print(f"Coverage data saved to: {args.coverage_file}")
        else:
            print(f"No coverage data found at {args.coverage_file}")

        exit()

    if args.reset_coverage:
        if os.path.exists(args.coverage_file):
            os.remove(args.coverage_file)
            print(f"Coverage data reset. Starting fresh.\n")
        else:
            print("No file found to reset")
        exit()


    if os.path.exists(args.coverage_file):
        cov.load()
        print(f"Loading existing coverage data from {args.coverage_file}\n")


    cov.start()
    
    try:
        data = loads(args.str_json) 
        print(f"Output decoded data: {data} of type {type(data)}")
    except PerformanceBug as e:
        print(f"A performance bug has been triggered: {e}")
        log_full_traceback(e, "performance")
        bug_id = track_exception(e)
        bug_count[("performance", *bug_id)] += 1

    except InvalidityBug as e:
        print(f"An invalidity bug has been triggered: {e}")
        log_full_traceback(e, "invalidity")
        bug_id = track_exception(e)
        bug_count[("invalidity", *bug_id)] += 1

    except JSONDecodeError as e:
        print(f"An invalidity bug has been triggered: {e}")
        log_full_traceback(e, "invalidity")
        bug_id = track_exception(e)
        bug_count[("invalidity", *bug_id)] += 1

    except Exception as e:
        print(f"An unknown exception has been triggered. {e}")
        log_full_traceback(e, "bonus")
        traceback.print_exc()
        bug_id = track_exception(e)
        bug_count[("bonus", *bug_id)] += 1
    finally:

        cov.stop()
        cov.save()

    # Saving the logs of the bug count and more detailed bugs
    logs_dir = "logs"
    os.makedirs(logs_dir, exist_ok=True)
    csv_path = os.path.join(logs_dir, "bug_counts.csv")
    bug_count_to_csv(bug_count, csv_path)
    
    print("Saved bug count report and tracebacks for the bugs encountered!")
    print(f"Final bug count: {bug_count}")
        
    if args.show_coverage:
        print("\n" + "="*60)
        print("COVERAGE REPORT (ACCUMULATED)")
        print("="*60)


        cov.report(file=None, show_missing=True)
        print_full_coverage_summary(cov)
        print_missing_branches(cov)
        print(f"Coverage data saved to: {args.coverage_file}")

    else:
        print(f"\nCoverage data saved to: {args.coverage_file}")
        print(f"Run with --show-coverage to see the report or --coverage-summary to view accumulated coverage.")
