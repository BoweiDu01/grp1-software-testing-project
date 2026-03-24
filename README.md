## To run main (Recommended to build in venv)

### Windows

```cmd
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python fuzzer_script.py
```

### Linux / WSL / macOS

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 fuzzer_script.py
```

# CLI-only runtime notes

- Uses subprocess execution against a target binary (default: `./win-ipv4-parser.exe`).
- Default startup corpus is valid IPv4 seeds at `corpus/networking/valid_ipv4` for faster evaluation.
- Keeps MOPT probability adaptation and updates rewards from current interestingness decisions.
- Uses general mutation operators only (no structured/domain-specific mutation).
- Preserves dashboard style and output locations (`logs/`, `crashes/`, `corpus/`).

# Common options

```bash
python fuzzer_script.py --iterations 200 --timeout 2.5
python fuzzer_script.py --target ./win-ipv4-parser.exe --input-arg --ipstr
python fuzzer_script.py --corpus-dir corpus/networking/valid_ipv4 --dashboard-interval 5
python fuzzer_script.py --corpus-dir corpus
python fuzzer_script.py --timeout 0.3 --max-input-bytes 96 --mopt-update-interval 10
python fuzzer_script.py --worker-mode persistent --worker-count 3 --inflight-jobs 6
python fuzzer_script.py --auto-tune
python fuzzer_script.py --no-auto-tune --timeout 0.4 --worker-count 2 --inflight-jobs 4 --max-input-bytes 96
```

# Throughput tips

- Lower `--timeout` (for this target, `0.2` to `0.5` is much faster than long timeouts).
- Clamp input size with `--max-input-bytes` to avoid expensive pathological parses.
- Keep `--dashboard-interval` larger (for example `25` to `100`) to reduce console overhead.
- Use `--mopt-update-interval` (default `10`) so probability changes are visible earlier in shorter runs.
- Use `--worker-mode persistent` with multiple workers and in-flight jobs for higher aggregate exec/s.
- Auto-tune is enabled by default and picks timeout/worker/inflight/input-size from machine heuristics.

# Expected Outputs

- `logs/bug_counts.csv` (owned/populated by the target binary; fuzzer only clears it at startup)
- `logs/traceback.log`
- `crashes/*.bin` and `crashes/*.json`

# To run any target application (for verification of inputs)

.\win-ipv4-parser.exe --ipstr "insert string here"
