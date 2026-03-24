## To run main (Recommended to build in venv)
py -m venv venv
npm build
.\venv\Scripts\Activate.ps1
py run fuzzer_script.py   

# Expected Outputs
logs folder containing bugs_count.csv and traceback.log

# To run any target application (for verification of inputs)
.\win-ipv4-parser.exe --ipstr "insert string here" 
