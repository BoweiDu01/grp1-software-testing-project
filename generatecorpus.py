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
        "169.254.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "63.63.63.63",
        "64.64.64.64",
        "127.127.127.127",
        "128.128.128.128",
        "193.193.193.193",
        "194.194.194.194",
        "1.255.1.255",
        "255.1.255.1",
    ]

    invalid = [
        "256.1.1.1",
        "1.1.1.256",
        "-1.1.1.1",
        "999.999.999.999",
        "1.1.1",
        "1.1.1.1.1",
        "1..1.1",
        "1.1.1.",
        ".1.1.1",
        "1,1,1,1",
        "1:1:1:1",
        "1 1 1 1",
        "1.1.1.A",
        "0x7f000001",
        "0177.0.0.1",
        "1.1.1.1/24",
        "1.1.1.1-2",
        "1.1.1.1\x00",
        "1.1.\n1.1",
        "",
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
        valid_stratified.append(
            ".".join(str(rng.choice(corners)) for _ in range(4)))

    return {
        "networking/ipv4_boundary": ("ipv4_boundary", "txt", boundary),
        "networking/ipv4_invalid": ("ipv4_invalid", "txt", invalid),
        "networking/ipv4_stratified": ("ipv4_valid", "txt", valid_stratified),
        # Compatibility path used by fuzzer default corpus-dir.
        "networking/valid_ipv4": ("seed", "txt", valid_stratified),
    }


def build_ipv6_seeds(rng, settings):
    boundary = [
        "::",
        "::1",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001:db8::1",
        "::ffff:192.168.0.1",
        "fe80::1",
        "ff00::1",
    ]

    invalid = [
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001:::1",
        "gggg::1",
        "::ffff:999.1.1.1",
        "12345::1",
        "::1::",
        "2001:db8",
        "",
    ]

    valid = [
        "2001:db8:85a3:0:0:8a2e:370:7334",
        "2001:db8::8a2e:370:7334",
        "fd00::1",
        "2001:db8:0:1::1",
        "::ffff:10.0.0.1",
    ]

    for _ in range(settings["stratified_per_bucket"]):
        hextets = [f"{rng.randint(0, 65535):x}" for _ in range(8)]
        valid.append(":".join(hextets))

    return {
        "networking/ipv6_boundary": ("ipv6_boundary", "txt", boundary),
        "networking/ipv6_invalid": ("ipv6_invalid", "txt", invalid),
        "networking/ipv6_valid": ("ipv6_valid", "txt", valid),
    }


def build_json_seeds(rng, settings):
    valid = [
        "{}",
        "[]",
        '{"ip":"127.0.0.1","ok":true}',
        '{"a": {"b": {"c": [1,2,3]}}}',
        '{"unicode":"\\u2764","escape":"line\\nnext"}',
        '{"numbers":[0,-1,1.23,1e10],"null":null}',
        "{" + ", ".join([f'\"key{i}\": {i}' for i in range(30)]) + "}",
    ]

    invalid = [
        '{"a":1',
        '{a:1}',
        '{"a":}',
        '{"a",1}',
        '[1,2,3',
        '[,1,2]',
        '{"ip":"127.0.0.1" "x":1}',
        '{"x":"\\uZZZZ"}',
        "{'single': 'quotes'}",
        "",
    ]

    for _ in range(settings["json_extra_count"]):
        size = rng.randint(3, 16)
        items = [f'\"k{i}\":{rng.randint(-1000, 1000)}' for i in range(size)]
        valid.append("{" + ",".join(items) + "}")

    return {
        "serialization/json_valid": ("json_valid", "json", valid),
        "serialization/json_invalid": ("json_invalid", "json", invalid),
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

    return {
        "agnostic/strings_valid": ("strings_valid", "txt", valid),
        "agnostic/strings_stress": ("strings_stress", "txt", stress),
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
