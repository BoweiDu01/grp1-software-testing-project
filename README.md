## To run main

### Windows

```cmd
go build mopt_fuzzer_max_executions.go
.\mopt_fuzzer_max_executions --driver .\drivers\json_whitebox.json --workers 1 --seed 42 --max-executions 5000
```

### Linux / WSL / macOS

```bash
go build mopt_fuzzer_max_executions.go
./mopt_fuzzer_max_executions --driver ./drivers/json_whitebox.json --workers 1 --seed 42 --max-executions 5000
```

# Using Drivers

The fuzzer is driven by JSON configuration files inside the `drivers/` directory. Each file specifies the target binary/script, how to pass inputs (e.g., via `argv`), arguments, timeouts, and the starting corpus directory.

To test a different target, pass the corresponding JSON file to the `--driver` flag. Available drivers include:

- `drivers/ipv4_blackbox.json`
- `drivers/ipv6_blackbox.json`
- `drivers/cidrize.json`
- `drivers/json_whitebox.json`

Example:

```bash
./mopt_fuzzer_max_executions --driver ./drivers/ipv4_blackbox.json --workers 4 --seed 42 --max-executions 10000
```

# Corpus generation

```bash
python generatecorpus.py
```

- The generator now builds a generic preset corpus across IPv4, IPv6, JSON, and string inputs.

# Throughput tips

- Use `--workers` to leverage multiple CPU cores for higher aggregate exec/s.

# Expected Outputs

- `logs/bug_counts.csv` (owned/populated by the target binary; the fuzzer preserves it across runs if it already exists)
- `logs/traceback.log`
- `logs/bug_repro_ledger.csv`
- `crashes/*.bin` and `crashes/*.json`

# To run any target application (for verification of inputs)

.\win-ipv4-parser.exe --ipstr "insert string here"


# To run baseline

you will need these packages  
sudo apt install python3-dev build-essential  
sudo apt install --no-install-recommends afl++ (For light installation 500mb~)

check core pattern by using `cat /proc/sys/kernel/core_pattern`

if you get something like `|/wsl-capture-crash %t %E %p %s`, AFL++ may not run properly. Quick fix is AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 but we dont want that.

`echo core | sudo tee /proc/sys/kernel/core_pattern`

Restore  
echo '|/wsl-capture-crash %t %E %p %s' | sudo tee /proc/sys/kernel/core_pattern

# For binary QEMU
git clone https://github.com/AFLplusplus/AFLplusplus  
cd AFLplusplus  
install any packages if needed  
make distrib

make sure `[+] libqasan ready [+] All done for qemu_mode, enjoy!`

Chances are you were missing some dependencies before the above happens