import os
import random
import shutil
import stat

# Minimal user input: edit this config only.
USER_CONFIG = {
    "output_root": "corpus",
    "profile": "balanced",  # quick | balanced | thorough
    "enabled_targets": {
        "ipv4": True,
        "ipv6": True,
        "cidr": True,
        "json": True,
        "strings": True,
    },
    "random_seed": 42,
}

PROFILE_SETTINGS = {
    "quick": {
        "stratified_per_bucket": 8,
        "mixed_corner_count": 8,
        "json_extra_count": 8,
        "string_extra_count": 12,
    },
    "balanced": {
        "stratified_per_bucket": 20,
        "mixed_corner_count": 20,
        "json_extra_count": 20,
        "string_extra_count": 28,
    },
    "thorough": {
        "stratified_per_bucket": 40,
        "mixed_corner_count": 40,
        "json_extra_count": 40,
        "string_extra_count": 56,
    },
}

IPV4_BUCKETS = [
    (0, 63),
    (64, 127),
    (128, 193),
    (194, 255),
]


def remove_readonly(func, path, _):
    """Clear the readonly bit and reattempt the removal"""
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _reset_root(path):
    if os.path.isdir(path):
        # Pass the error handler to forcefully delete stubborn Windows files
        shutil.rmtree(path, onerror=remove_readonly)
    os.makedirs(path, exist_ok=True)


def _write_seed_list(base_dir, relative_dir, prefix, extension, seeds):
    target_dir = os.path.join(base_dir, relative_dir)
    os.makedirs(target_dir, exist_ok=True)

    # Keep deterministic ordering and remove duplicates.
    ordered_unique = list(dict.fromkeys(seeds))
    for idx, seed in enumerate(ordered_unique, start=1):
        file_name = f"{prefix}_{idx:04d}.{extension}"
        file_path = os.path.join(target_dir, file_name)
        
        # Check if the seed is raw bytes (like our BOM seed) or a standard string
        if isinstance(seed, bytes):
            with open(file_path, "wb") as f:
                f.write(seed)
        else:
            with open(file_path, "w", encoding="utf-8", newline="") as f:
                f.write(seed)
                
    print(f"Generated {len(ordered_unique):4d} seeds in {relative_dir}")


def _rand_ipv4(rng, lo, hi):
    return ".".join(str(rng.randint(lo, hi)) for _ in range(4))


def build_ipv4_seeds(rng, settings):
    boundary = [
        "0.0.0.0", "255.255.255.255", "127.0.0.1", "169.254.0.0",
        "224.0.0.1", "240.0.0.1", "63.63.63.63", "64.64.64.64",
        "127.127.127.127", "128.128.128.128", "193.193.193.193",
        "194.194.194.194", "1.255.1.255", "255.1.255.1",
    ]

    invalid = [
        "256.1.1.1", "1.1.1.256", "-1.1.1.1", "999.999.999.999",
        "1.1.1", "1.1.1.1.1", "1..1.1", "1.1.1.", ".1.1.1",
        "1,1,1,1", "1:1:1:1", "1 1 1 1", "1.1.1.A", "0x7f000001",
        "0177.0.0.1", "1.1.1.1/24", "1.1.1.1-2", "1.1.1.1\x00",
        "1.1.\n1.1", "",
    ]

    valid_stratified = []
    per_bucket = settings["stratified_per_bucket"]
    for lo, hi in IPV4_BUCKETS:
        valid_stratified.append(f"{lo}.{lo}.{lo}.{lo}")
        valid_stratified.append(f"{hi}.{hi}.{hi}.{hi}")
        for _ in range(per_bucket):
            valid_stratified.append(_rand_ipv4(rng, lo, hi))

    corners = [0, 1, 63, 64, 127, 128, 193, 194, 254, 255]
    for _ in range(settings["mixed_corner_count"]):
        valid_stratified.append(".".join(str(rng.choice(corners)) for _ in range(4)))

    # UPDATED DICTIONARY KEYS
    return {
        "ipv4/boundary": ("ipv4_boundary", "txt", boundary),
        "ipv4/invalid": ("ipv4_invalid", "txt", invalid),
        "ipv4/stratified": ("ipv4_valid", "txt", valid_stratified),
        "ipv4/seed": ("seed", "txt", valid_stratified),
    }


def build_ipv6_seeds(rng, settings):
    boundary = [
        "::", "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001:db8::1", "::ffff:192.168.0.1", "fe80::1", "ff00::1",
    ]

    invalid = [
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001:::1", "gggg::1", "::ffff:999.1.1.1",
        "12345::1", "::1::", "2001:db8", "",
    ]

    valid = [
        "2001:db8:85a3:0:0:8a2e:370:7334", "2001:db8::8a2e:370:7334",
        "fd00::1", "2001:db8:0:1::1", "::ffff:10.0.0.1",
    ]

    for _ in range(settings["stratified_per_bucket"]):
        hextets = [f"{rng.randint(0, 65535):x}" for _ in range(8)]
        valid.append(":".join(hextets))

    # UPDATED DICTIONARY KEYS
    return {
        "ipv6/boundary": ("ipv6_boundary", "txt", boundary),
        "ipv6/invalid": ("ipv6_invalid", "txt", invalid),
        "ipv6/valid": ("ipv6_valid", "txt", valid),
    }

def build_cidr_seeds(rng, settings):
    valid = [
        "192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12",
        "2001:db8::/32", "fe80::/10", "2000::/3"
    ]
    
    boundary = [
        "0.0.0.0/0", "255.255.255.255/32", "127.0.0.1/8", "224.0.0.0/4",
        "::/0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "::1/128"
    ]
    
    anomalies = [
        "192.168.1.0/33", "10.0.0.0/255", "::1/129", "2001:db8::/999",
        "10.0.0.0/-1", "fe80::/-24", "192.168.1.0/024", "10.0.0.0/0x18",
        "192.168.1.0/", "/24", "10.0.0.0//24", "192.168.1.0/24/16", 
        " 10.0.0.0/24 ", "10.0.0.0 / 24", "192.168.1.0/abc", "10.0.0.0/!@#"
    ]

    # UPDATED DICTIONARY KEYS
    return {
        "cidr/valid": ("cidr_valid", "txt", valid),
        "cidr/boundary": ("cidr_boundary", "txt", boundary),
        "cidr/anomalies": ("cidr_anomalies", "txt", anomalies),
    }


def build_json_seeds(rng, settings):
    valid = [
        '{"ip":"127.0.0.1","ok":true}',
        "{" + ", ".join([f'\"key{i}\": {i}' for i in range(10)]) + "}",
        '{"level1": {"level2": {"level3": {"level4": [1, 2, {"level6": "deep"}]}}}}',
        '[1, "string", true, false, null, {"key": "value"}, [1.1, 2.2]]',
        '{"sci1": 1e10, "sci2": -2.5E-4, "sci3": 0e0}',
        '{"zero": 0, "neg_zero": -0, "decimal": 0.123456789, "large": 999999999999999999999}',
        '{"escapes": "\\" \\\\ \\/ \\b \\f \\n \\r \\t"}',
        '{"unicode": "\\u00A9 \\u2764 \\uD83D\\uDE00"}',
        '{   "key"   :   [   1   ,   2   ]   }',
        '{\n\t"tabbed":\t"value",\n\t"newline": "next\\nline"\n}',
        '{}',
        '[]',
        '{"exp": 1e+10}',
        '{"a": "\\u"}',
        '{"a": 1,}',
        '[1, 2, ]',
        '{"math": [NaN, Infinity, -Infinity]}',
        '{"emoji": "\\uD83D\\uDE00"}',
        b'\xef\xbb\xbf{"bom": "utf-8"}'
    ]

    invalid = [
        '{"a":1', '{a:1}', '{"a":}', '{"a",1}', '[1,2,3',
        '[,1,2]', '{"ip":"127.0.0.1" "x":1}', '{"x":"\\uZZZZ"}',
        "{'single': 'quotes'}", "",
    ]

    for _ in range(settings["json_extra_count"]):
        size = rng.randint(3, 16)
        items = [f'\"k{i}\":{rng.randint(-1000, 1000)}' for i in range(size)]
        valid.append("{" + ",".join(items) + "}")

    # UPDATED DICTIONARY KEYS
    return {
        "json/valid": ("json_valid", "json", valid),
        "json/invalid": ("json_invalid", "json", invalid),
    }


def build_string_seeds(rng, settings):
    valid = [
        "hello world",
        " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
        "GET /index.html HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n",
        "id,val,type\\n1,10.5,A\\n2,,B\\n3,99.9,C",
        "[user]\\nname=seed\\nadmin=0",
        "function test(x) { return (x > 0) ? [1,2,3] : null; }",
        "SGVsbG8gV29ybGQgRnV6emVyIQ==",
    ]

    stress = [
        "A" * 256,
        "A" * 512,
        "A" * 1024,
        "\\x00",
        "\\x00" * 16,
        "\\t\\n\\r " * 32,
        "." * 64,
        ":" * 64,
        "/" * 64,
    ]

    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789.:/_- "
    for _ in range(settings["string_extra_count"]):
        ln = rng.randint(8, 96)
        stress.append("".join(rng.choice(alphabet) for _ in range(ln)))

    # UPDATED DICTIONARY KEYS
    return {
        "strings/valid": ("strings_valid", "txt", valid),
        "strings/stress": ("strings_stress", "txt", stress),
    }


def create_fuzzing_corpus(config=None):
    cfg = dict(USER_CONFIG)
    if config:
        cfg.update(config)

    profile = cfg.get("profile", "balanced")
    if profile not in PROFILE_SETTINGS:
        raise ValueError(f"Unknown profile: {profile}")

    settings = PROFILE_SETTINGS[profile]
    rng = random.Random(int(cfg.get("random_seed", 42)))
    root = cfg.get("output_root", "corpus")
    enabled = cfg.get("enabled_targets", {})

    _reset_root(root)
    print(f"Prepared fresh corpus root: {root}")
    print(f"Profile: {profile}\n")

    groups = {}
    if enabled.get("ipv4", True):
        groups.update(build_ipv4_seeds(rng, settings))
    if enabled.get("ipv6", True):
        groups.update(build_ipv6_seeds(rng, settings))
    if enabled.get("cidr", True):
        groups.update(build_cidr_seeds(rng, settings))
    if enabled.get("json", True):
        groups.update(build_json_seeds(rng, settings))
    if enabled.get("strings", True):
        groups.update(build_string_seeds(rng, settings))

    total_files = 0
    for rel_dir, (prefix, ext, seeds) in groups.items():
        _write_seed_list(root, rel_dir, prefix, ext, seeds)
        total_files += len(dict.fromkeys(seeds))

    print(f"\nCorpus generation complete. Total seed files: {total_files}")


if __name__ == "__main__":
    create_fuzzing_corpus()