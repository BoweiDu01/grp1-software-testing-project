@echo off

@REM Because your new target is a Python script (json_decoder_stv.py) and not a compiled Windows binary (win-ipv4-parser.exe),
@REM  there is a slight catch with how Python's subprocess.run() handles execution under the hood.

@REM The fuzzer currently constructs its execution command like this: [binary_path, input_arg, input_text]. 
@REM If you pass a Python script directly as the binary_path, the operating system won't know how to run it 
@REM without the python or uv run command preceding it.

python run json_decoder_stv.py %* --show-coverage