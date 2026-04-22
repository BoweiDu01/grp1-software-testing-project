import os

def generate_json_corpus():
    # Target directory matching your fuzzer's configuration
    corpus_dir = os.path.join("corpus", "serialization", "json_new")
    
    # Ensure the directory exists
    os.makedirs(corpus_dir, exist_ok=True)

    # Standard text-based seeds
    text_seeds = {
        "nested.json": '{"level1": {"level2": {"level3": {"level4": [1, 2, {"level6": "deep"}]}}}}',
        "mixed_arrays.json": '[1, "string", true, false, null, {"key": "value"}, [1.1, 2.2]]',
        "scientific_numbers.json": '{"sci1": 1e10, "sci2": -2.5E-4, "sci3": 0e0}',
        "edge_numbers.json": '{"zero": 0, "neg_zero": -0, "decimal": 0.123456789, "large": 999999999999999999999}',
        "escapes.json": '{"escapes": "\\" \\\\ \\/ \\b \\f \\n \\r \\t"}',
        "unicode.json": '{"unicode": "\\u00A9 \\u2764 \\uD83D\\uDE00"}',
        "heavy_whitespace.json": '{   "key"   :   [   1   ,   2   ]   }',
        "newlines_tabs.json": '{\n\t"tabbed":\t"value",\n\t"newline": "next\\nline"\n}',
        "empty_obj.json": '{}',
        "empty_arr.json": '[]',
        
        # --- THE NEW GOLDEN SEEDS (TEXT) ---
        
        # Unquoted constants that the scanner explicitly looks for
        "constants.json": '{"math": [NaN, Infinity, -Infinity]}',
        
        # Isolated surrogate pair to ensure the fuzzer hits the 0xd800 check
        "surrogate_only.json": '{"emoji": "\\uD83D\\uDE00"}'
    }

    # Binary-based seeds for exact byte-level control
    binary_seeds = {
        # --- THE NEW GOLDEN SEED (BINARY) ---
        
        # UTF-8 Byte-Order Mark (\xef\xbb\xbf) attached to a simple JSON object
        "bom_utf8.json": b'\xef\xbb\xbf{"bom": "utf-8"}'
    }

    print(f"Generating JSON seeds in '{corpus_dir}'...")
    
    # Write the text seeds
    for filename, content in text_seeds.items():
        file_path = os.path.join(corpus_dir, filename)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f" [+] Created {filename} ({len(content)} bytes)")

    # Write the binary seeds
    for filename, content in binary_seeds.items():
        file_path = os.path.join(corpus_dir, filename)
        with open(file_path, "wb") as f: # Note the "wb" mode for write-binary
            f.write(content)
        print(f" [+] Created {filename} (BINARY) ({len(content)} bytes)")

    print("\nSeed generation complete! You can now run your fuzzer.")

if __name__ == "__main__":
    generate_json_corpus()