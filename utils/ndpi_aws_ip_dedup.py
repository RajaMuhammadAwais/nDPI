#!/usr/bin/env python3
"""
Assign Amazon AWS IP prefixes to per-service nDPI lists without duplicates.

Issue: many prefixes in ip-ranges.json are tagged with multiple service
labels (for example "AMAZON" + "EC2" + "S3"). The previous jq selectors in
utils/aws_ip_addresses_download.sh assigned the same prefix to several
generated lists at the same time (2284 duplicated entries between the
AMAZON_AWS and AWS_EC2 lists, see GitHub issue #3062).

This script implements a single-owner precedence rule, similar to the one
used by nDPI for the Microsoft address lists in the past:

    EC2_INSTANCE_CONNECT > EC2 > S3 > CLOUDFRONT > DYNAMODB >
    API_GATEWAY > KINESIS_VIDEO_STREAMS > AMAZON_AWS (generic)

Each prefix is emitted into exactly one list. Prefixes that are not tagged
with any of the specific services above stay in the generic AMAZON_AWS
list.

Usage:
    ndpi_aws_ip_dedup.py <ip-ranges.json> <output_dir>

Output: <output_dir>/<SERVICE>.list / <SERVICE>6.list files, one prefix per
line (CIDR notation, IPv4 first then IPv6), ready to be fed to
ipaddr2list.py through mergeipaddrlist.py, exactly like the previous
workflow.
"""
import ipaddress
import json
import os
import sys
from collections import defaultdict

PRECEDENCE = [
    "EC2_INSTANCE_CONNECT",
    "EC2",
    "S3",
    "CLOUDFRONT",
    "DYNAMODB",
    "API_GATEWAY",
    "KINESIS_VIDEO_STREAMS",
]
GENERIC = "AMAZON_AWS"

if len(sys.argv) != 3:
    print("Usage: ndpi_aws_ip_dedup.py <ip-ranges.json> <output_dir>")
    sys.exit(1)

src, outdir = sys.argv[1], sys.argv[2]
data = json.load(open(src))

def per_prefix(prefixes, key):
    """Map each prefix string to the set of service tags it carries."""
    tags = defaultdict(set)
    for entry in prefixes:
        tags[entry[key]].add(entry["service"])
    return tags

def assign(tags):
    """Return a map prefix -> owning service using the precedence rule."""
    owner = {}
    for pfx, svc_tags in tags.items():
        for svc in PRECEDENCE:
            if svc in svc_tags:
                owner[pfx] = svc
                break
        else:
            owner[pfx] = GENERIC
    return owner

def write_lists(prefixes, key, suffix):
    """Emit one deduplicated <SERVICE><suffix>.list per service, plain CIDR
    lines consumable by the existing mergeipaddrlist.py / ipaddr2list.py
    pipeline. suffix is '' for IPv4 and '6' for IPv6, matching the naming
    used by the sibling utils scripts."""
    tags = per_prefix(prefixes, key)
    owner = assign(tags)
    buckets = defaultdict(list)
    for pfx, svc in owner.items():
        buckets[svc].append(ipaddress.ip_network(pfx))
    for svc in PRECEDENCE + [GENERIC]:
        nets = sorted(buckets.get(svc, []))
        merged = ipaddress.collapse_addresses(nets)
        merged = sorted(merged, key=lambda n: (n.network_address.packed, n.prefixlen))
        dest = os.path.join(outdir, f"{svc}{suffix}.list")
        with open(dest, "w") as fp:
            for net in merged:
                fp.write(f"{net}\n")
        print(f"wrote {dest} ({len(merged)} prefixes)")

write_lists(data["prefixes"], "ip_prefix", "")
write_lists(data["ipv6_prefixes"], "ipv6_prefix", "6")
