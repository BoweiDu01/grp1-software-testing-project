import os

def create_fuzzing_corpus():
    # Define the directory structure
    base_dir = "corpus"
    sub_dirs = ["networking", "serialization", "agnostic"]
    
    # Ensure directories exist
    for sub in sub_dirs:
        path = os.path.join(base_dir, sub)
        os.makedirs(path, exist_ok=True)
        print(f"Prepared folder: {path}")

    # --- 1. Networking Seeds (Tailored for IP/CIDR Parsers) ---
    nw_seeds = {
        "ipv4_std.txt": "127.0.0.1",
        "ipv4_edge.txt": "255.255.255.255",
        "ipv4_zero.txt": "0.0.0.0",
        "ipv6_std.txt": "::1",
        "ipv6_full.txt": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "ipv6_comp.txt": "2001:db8::1",
        "dual_stack.txt": "::192.168.0.1",
        "cidr.txt": "10.0.0.0/8",
        "range_dash.txt": "192.168.1.1-254",
        "range_wild.txt": "192.168.1.[0-255]",
        "ip_octal.txt": "0177.0.0.1",
        "ip_hex.txt": "0x7f000001"
    }

    # --- 2. Serialization Seeds (Tailored for JSON Decoder) ---
    json_seeds = {
        "empty_types.json": '{"a": {}, "b": [], "c": "", "d": null}',
        "deep_nest.json": "[[[[[[{'a':1}]]]]]]",
        "data_types.json": '{"int": 9223372036854775807, "float": 1.23e10, "unicode": "\\u2764", "bool": true}',
        "large_obj.json": "{" + ", ".join([f'"key{i}": {i}' for i in range(100)]) + "}"
    }

    # --- 3. Agnostic/General ASCII Seeds ---
    agnostic_seeds = {
        "ascii_full.txt": " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
        "table.csv": "id,val,type\n1,10.5,A\n2,,B\n3,99.9,C",
        "config.ini": "[user]\nname=bowei\nadmin=1\n[server]\nport=8080",
        "web.html": "<div id='main'><p class='text'>Hello World</p></div>",
        "code.js": "function test(x) { return (x > 0) ? [1,2,3] : null; }",
        "web_header.txt": "GET /index.html HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Fuzzer\r\n\r\n",
        "base64.txt": "SGVsbG8gV29ybGQgRnV6emVyIQ==",
        "overflow_base.txt": "A" * 512  # A medium-sized block to start overflow mutations
    }

    # Helper function to write files
    def write_files(directory, seed_dict):
        for filename, content in seed_dict.items():
            file_path = os.path.join(base_dir, directory, filename)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  Generated: {filename}")

    # Execute writing
    write_files("networking", nw_seeds)
    write_files("serialization", json_seeds)
    write_files("agnostic", agnostic_seeds)

    print("\nSuccessfully created seed corpus for all 3 target applications!")

if __name__ == "__main__":
    create_fuzzing_corpus()