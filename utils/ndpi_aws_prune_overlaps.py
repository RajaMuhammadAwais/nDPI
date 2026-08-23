#!/usr/bin/env python3
"""
Remove cross-list address overlaps introduced by cidr merging.

Even after each prefix is assigned to exactly one service
(ndpi_aws_ip_dedup.py), merging adjacent prefixes inside a single list
(netaddr.cidr_merge in mergeipaddrlist.py) can produce a network that
partially or fully covers a prefix kept in a lower-precedence list.
For example, CloudFront-owned rows may merge into 52.82.128.0/19 while
the generic AMAZON_AWS list still keeps its own 52.82.128.0/23 block,
which is fully contained inside the merged /19 (GitHub issue #3062).

This post-processor trims the lower-precedence lists so that no address
in them is covered by a network in a higher-precedence list. It works on
the already merged list files emitted by mergeipaddrlist.py, so the
existing pipeline stays untouched.

Precedence (same as ndpi_aws_ip_dedup.py):
    EC2_INSTANCE_CONNECT > EC2 > S3 > CLOUDFRONT > DYNAMODB >
    API_GATEWAY > KINESIS_VIDEO_STREAMS > AMAZON_AWS (generic)

Usage:
    ndpi_aws_prune_overlaps.py <merged_dir> [suffix]

Expects the merged pair files <SERVICE><suffix> / <SERVICE><suffix6> in
<merged_dir> and overwrites them in place, in precedence order.
The default suffix is empty / "6" (the raw dedup output); pass "m" /
"m6" to operate on the mergeipaddrlist.py merged files.
Prefixes removed from a lower-precedence list because they are covered
by a higher-precedence network are printed to stderr for auditing.
"""
import ipaddress
import os
import sys

PRECEDENCE = [
    "EC2_INSTANCE_CONNECT",
    "EC2",
    "S3",
    "CLOUDFRONT",
    "DYNAMODB",
    "API_GATEWAY",
    "KINESIS_VIDEO_STREAMS",
    "AMAZON_AWS",
]

if len(sys.argv) not in (2, 3):
    print("Usage: ndpi_aws_prune_overlaps.py <merged_dir> [suffix]")
    sys.exit(1)

# The suffix only ever takes two trusted values: empty (default) or
# "m" (the mergeipaddrlist.py output) for the four file pairs below.
# Reject anything else before it can reach the filesystem
# (GitHub issue #3062, SonarCloud pythonsecurity:S8707).
KNOWN_SUFFIXES = ("", "m")
suffix = sys.argv[2] if len(sys.argv) == 3 else ""
if suffix not in KNOWN_SUFFIXES:
    print(f"unsupported suffix {suffix!r} (expected '' or 'm')")
    sys.exit(1)

merged_dir = sys.argv[1]

def resolve_path(name, path):
    """Resolve a CLI-supplied path and make sure it stays inside the
    current working directory (GitHub issue #3062, SonarCloud
    pythonsecurity:S8707)."""
    real = os.path.realpath(path)
    cwd = os.path.realpath(os.getcwd())
    if not real.startswith(cwd + os.sep) and real != cwd:
        print(f"{name}: {path} resolves outside the working directory")
        sys.exit(1)
    return real

merged_dir = resolve_path("merged_dir", merged_dir)

# Collect all networks of higher-precedence lists as we walk the chain.
protected = []

def covered_by(net, others):
    return any(other.supernet_of(net) for other in others)

for kind in ("." + suffix, "." + suffix + "6"):
    for svc in PRECEDENCE:
        path = os.path.realpath(os.path.join(merged_dir, f"{svc}{kind}"))
        base = os.path.realpath(merged_dir) + os.sep
        # svc comes from the PRECEDENCE constant and kind is a known
        # value, so a path that escapes the merged directory is only
        # possible when merged_dir itself is hostile; catch it before
        # touching the filesystem (GitHub issue #3062,
        # SonarCloud pythonsecurity:S8707).
        if not path.startswith(base):
            print(f"prune: skip {path} outside the merged directory",
                  file=sys.stderr)
            continue
        if not os.path.exists(path):
            print(f"prune: skip missing {path}", file=sys.stderr)
            continue
        nets = [ipaddress.ip_network(line.strip())
                for line in open(path) if line.strip()]
        print(f"prune: {path}: {len(nets)} entries",
              file=sys.stderr)
        kept = []
        removed = 0
        for net in nets:
            if covered_by(net, protected):
                removed += 1
                print(f"removing {net} from {svc}{kind} "
                      f"(covered by a higher-precedence list)",
                      file=sys.stderr)
            else:
                kept.append(net)
        protected.extend(kept)
        if removed:
            print(f"pruned {removed} covered entries from {svc}{kind}",
                  file=sys.stderr)
        with open(path, "w") as fp:
            for net in sorted(kept,
                              key=lambda n: (n.network_address.packed,
                                             n.prefixlen)):
                fp.write(f"{net}\n")

print("cross-list overlap pruning complete")
