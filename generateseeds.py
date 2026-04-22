import os

def generate_json_corpus():
    # Target directory matching your fuzzer's configuration
    corpus_dir = os.path.join("corpus", "serialization", "json_new")
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
        "explicit_exponent.json": '{"exp": 1e+10}',
        "eof_unicode.json": '{"a": "\\u"}',
        "trailing_comma_obj.json": '{"a": 1,}',
        "trailing_comma_arr.json": '[1, 2, ]',
        "constants.json": '{"math": [NaN, Infinity, -Infinity]}',
        "surrogate_only.json": '{"emoji": "\\uD83D\\uDE00"}'
    }

    # Binary-based seeds for exact byte-level control
    binary_seeds = {
        "bom_utf8.json": b'\xef\xbb\xbf{"bom": "utf-8"}'
    }

    print(f"Generating JSON seeds in '{corpus_dir}'...")
    for filename, content in text_seeds.items():
        with open(os.path.join(corpus_dir, filename), "w", encoding="utf-8") as f:
            f.write(content)
            
    for filename, content in binary_seeds.items():
        with open(os.path.join(corpus_dir, filename), "wb") as f:
            f.write(content)
            
    print(f" [+] Generated {len(text_seeds) + len(binary_seeds)} JSON seeds.\n")

def generate_cidr_corpus():
    # Target directory for CIDR fuzzing
    corpus_dir = os.path.join("corpus", "networking", "cidr_seeds")
    os.makedirs(corpus_dir, exist_ok=True)

    cidr_seeds = {
        # 1. Valid Baselines (The "Happy Path")
        "v4_local.txt": "192.168.1.0/24",
        "v4_private_large.txt": "10.0.0.0/8",
        "v4_private_std.txt": "172.16.0.0/12",
        "v6_doc.txt": "2001:db8::/32",
        "v6_link_local.txt": "fe80::/10",
        "v6_global.txt": "2000::/3",

        # 2. Boundary and Edge Cases
        "v4_any.txt": "0.0.0.0/0",
        "v4_max_host.txt": "255.255.255.255/32",
        "v4_loopback.txt": "127.0.0.1/8",
        "v4_multicast.txt": "224.0.0.0/4",
        "v6_any.txt": "::/0",
        "v6_max.txt": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
        "v6_loopback.txt": "::1/128",

        # 3. Prefix Length Anomalies
        "v4_out_of_bounds_low.txt": "192.168.1.0/33",
        "v4_out_of_bounds_high.txt": "10.0.0.0/255",
        "v6_out_of_bounds_low.txt": "::1/129",
        "v6_out_of_bounds_high.txt": "2001:db8::/999",
        "v4_negative.txt": "10.0.0.0/-1",
        "v6_negative.txt": "fe80::/-24",
        "v4_octal_pad.txt": "192.168.1.0/024",
        "v4_hex_inject.txt": "10.0.0.0/0x18",
        "v4_missing_prefix.txt": "192.168.1.0/",
        "v4_missing_ip.txt": "/24",

        # 4. Structural & Delimiter Messes
        "mess_double_slash.txt": "10.0.0.0//24",
        "mess_triple_segment.txt": "192.168.1.0/24/16",
        "mess_whitespace_outer.txt": " 10.0.0.0/24 ",
        "mess_whitespace_inner.txt": "10.0.0.0 / 24",
        "mess_type_confusion_str.txt": "192.168.1.0/abc",
        "mess_type_confusion_sym.txt": "10.0.0.0/!@#"
    }

    print(f"Generating CIDR seeds in '{corpus_dir}'...")
    for filename, content in cidr_seeds.items():
        with open(os.path.join(corpus_dir, filename), "w", encoding="ascii") as f:
            f.write(content)
            
    print(f" [+] Generated {len(cidr_seeds)} CIDR seeds.\n")

if __name__ == "__main__":
    generate_json_corpus()
    generate_cidr_corpus()
    print("Seed generation complete! You can now run your fuzzer.")