#!/usr/bin/env python3
import json
import os
import random
import shutil

# Minimal user input: edit this config only.
USER_CONFIG = {
    "output_root": "corpus",
    "profile": "balanced",  # quick | balanced | thorough
    "enabled_targets": {
        "ipv4": True,
        "ipv6": True,
        "cidr": True,       # Added explicitly
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


def _reset_root(path):
    if os.path.isdir(path):
        shutil.rmtree(path)
    os.makedirs(path, exist_ok=True)


def _write_seed_list(base_dir, relative_dir, prefix, extension, seeds):
    target_dir = os.path.join(base_dir, relative_dir)
    os.makedirs(target_dir, exist_ok=True)

    # Keep deterministic ordering and remove duplicates.
    ordered_unique = list(dict.fromkeys(seeds))
    for idx, seed in enumerate(ordered_unique, start=1):
        file_name = f"{prefix}_{idx:04d}.{extension}"
        file_path = os.path.join(target_dir, file_name)
        with open(file_path, "w", encoding="utf-8", newline="") as f:
            f.write(seed)
    print(f"Generated {len(ordered_unique):4d} seeds in {relative_dir}")


def _rand_ipv4(rng, lo, hi):
    return ".".join(str(rng.randint(lo, hi)) for _ in range(4))


def build_ipv4_seeds(rng, settings):
    boundary = [
        "0.0.0.0",
        "255.255.255.255",
        "127.0.0.1",
        "224.0.0.1",
    ]

    valid_stratified = []

    per_bucket = min(settings.get("stratified_per_bucket", 1), 2) 
    
    for lo, hi in IPV4_BUCKETS:
        valid_stratified.append(f"{lo}.{lo}.{lo}.{lo}")
        valid_stratified.append(f"{hi}.{hi}.{hi}.{hi}")
        for _ in range(per_bucket):
            valid_stratified.append(_rand_ipv4(rng, lo, hi))

    corners = [0, 1, 63, 64, 127, 128, 193, 194, 254, 255]
    
    corner_count = min(settings.get("mixed_corner_count", 5), 10)
    for _ in range(corner_count):
        valid_stratified.append(".".join(str(rng.choice(corners)) for _ in range(4)))

    combined_corpus = boundary + valid_stratified

    return {
        "networking/ipv4": ("ipv4", "txt", combined_corpus), 
    }


def build_ipv6_seeds(rng, settings):
    boundary = [
        "::1",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001:db8::1",
        "::ffff:192.168.0.1",
    ]

    valid = [
        "2001:db8:85a3:0:0:8a2e:370:7334",
        "fd00::1",
    ]

    for _ in range(settings["stratified_per_bucket"]):
        hextets = [f"{rng.randint(0, 65535):x}" for _ in range(8)]
        valid.append(":".join(hextets))

    return {
        "networking/ipv6": ("ipv6_valid", "txt", valid + boundary),
    }


def build_cidr_seeds(rng, settings):
    # Standard valid CIDR/IP seeds
    valid_seeds = [
        "192.168.1.0/24",
        "10.0.0.0/8",
        "0.0.0.0/0",
        "255.255.255.255/32",
        "127.0.0.1",     
        "::1/128",          
        "fd00::/8",
    ]

    precursor_seeds = [
        "192.168.1.1-10",
        "10.0.0.5-5",        
        "10.0.0.[1]",        
        "172.16.0.[a-z]",    
        "127.0.0.1//24",
        "1.2.3.4/99",
        "-1.0.0.0",          
        "192.168.01.001",    
        "30.0.0.1--1",       
        "10.0.0.1 192.168.1.1", 
        "10.0.0.1\t24",         
        "192.one.2.3",
        "server.localnet.com"
    ]
    
    per_bucket = settings["stratified_per_bucket"]
    for _ in range(per_bucket // 2):
        valid_seeds.append(f"{_rand_ipv4(rng, 0, 255)}/{rng.randint(0, 32)}")
        
    all_seeds = valid_seeds + precursor_seeds
    return {
        "networking/cidr_mixed": ("cidr", "txt", all_seeds),
    }


def _gen_nested_json_obj(rng, max_depth, current_depth=0):
    """Recursively generates complex JSON structures."""
    if current_depth >= max_depth or rng.random() < 0.2:
        # Base case: Return a leaf node
        return rng.choice([
            rng.randint(-10000, 10000),
            round(rng.uniform(-1000.0, 1000.0), 4),
            f"val_{rng.randint(0, 100)}",
            True, False, None
        ])
    
    if rng.random() < 0.5:
        # Generate a Dictionary
        size = rng.randint(1, 5)
        return {f"k_{i}": _gen_nested_json_obj(rng, max_depth, current_depth + 1) for i in range(size)}
    else:
        # Generate a List
        size = rng.randint(1, 5)
        return [_gen_nested_json_obj(rng, max_depth, current_depth + 1) for _ in range(size)]


def build_json_seeds(rng, settings):
    valid = [
        "{}",
        "[]",
        '{"ip":"127.0.0.1","ok":true}',
        '{"a": {"b": {"c": [1,2,3]}}}',
        '{"unicode":"\\u2764","escape":"line\\nnext"}',
        '{"numbers":[0,-1,1.23,1e10],"null":null}',
    ]

    for _ in range(settings["json_extra_count"]):
        depth = rng.randint(2, 6)
        obj = _gen_nested_json_obj(rng, max_depth=depth)
        
        if not isinstance(obj, (dict, list)):
            obj = {"root": obj}
            
        valid.append(json.dumps(obj, separators=(',', ':')))

    return {
        "serialization/json_valid": ("json_valid", "json", valid),
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
        "abc.def.ghi",         # Hostname-like
        "0-255",               # Range-like
        "[0-9]",               # Bracket range
    ]

    return {
        "agnostic/strings_valid": ("strings_valid", "txt", valid),
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
    print(f"Profile: {profile}")

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