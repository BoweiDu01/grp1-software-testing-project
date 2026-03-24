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

# Expected Outputs
logs folder containing bugs_count.csv and traceback.log

# To run any target application (for verification of inputs)
.\win-ipv4-parser.exe --ipstr "insert string here" 
