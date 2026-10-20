#!/usr/bin/env python3
"""Compare default/savedsearches.conf between two content-update packages.

Usage: compare_savedsearches.py --previous-version OLD_ARCHIVE --new-version NEW_ARCHIVE

Prints a table of every stanza (present in both packages) that changed, with
the action.correlationsearch.metadata detection_version bump and whether any
other field changed. Sorted by "Any other changes" (No first), then stanza name.

Exit code: 1 if at least one changed stanza has no changes beyond the
metadata field, else 0 (2 on usage/input errors).
"""
import argparse
import json
import os
import re
import sys
import tarfile
import tempfile

CONF_SUFFIX = os.path.join("default", "savedsearches.conf")
METADATA_KEY = "action.correlationsearch.metadata"


def extract(archive, dest):
    with tarfile.open(archive) as tar:
        for m in tar.getmembers():
            target = os.path.realpath(os.path.join(dest, m.name))
            if not target.startswith(os.path.realpath(dest) + os.sep):
                raise ValueError(f"unsafe path in archive: {m.name}")
            if m.issym() or m.islnk() or m.isdev():
                raise ValueError(f"unsupported member in archive: {m.name}")
        tar.extractall(dest)


def find_conf(root):
    for dirpath, _, files in os.walk(root):
        if "savedsearches.conf" in files and dirpath.endswith("default"):
            return os.path.join(dirpath, "savedsearches.conf")
    raise FileNotFoundError(f"no {CONF_SUFFIX} found under {root}")


def parse_conf(path):
    stanzas, cur = {}, None
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^\[(.+)\]\s*$", line)
        if m:
            cur = m.group(1)
            stanzas[cur] = {}
        elif cur is not None and "=" in line and not line.lstrip().startswith("#"):
            key, val = line.split("=", 1)
            val = val.lstrip()
            while val.endswith("\\") and i + 1 < len(lines):
                i += 1
                val = val[:-1] + "\n" + lines[i]
            stanzas[cur][key.strip()] = val.rstrip()
        i += 1
    return stanzas


def metadata(stanza):
    try:
        return json.loads(stanza.get(METADATA_KEY, "{}"))
    except json.JSONDecodeError:
        return {}


def compare(old, new):
    rows = []
    for name in set(old) & set(new):
        o, n = old[name], new[name]
        if o == n:
            continue
        other = sorted(k for k in set(o) | set(n) if k != METADATA_KEY and o.get(k) != n.get(k))
        ov = metadata(o).get("detection_version")
        nv = metadata(n).get("detection_version")
        rows.append({"name": name, "ov": ov, "nv": nv, "bump": ov != nv, "other": other})
    rows.sort(key=lambda r: (bool(r["other"]), r["name"].lower()))
    return rows


def print_table(rows):
    print("| Stanza Name | Version bump? | Version (old -> new) | Any other changes? | Other fields changed |")
    print("|---|---|---|---|---|")
    for r in rows:
        print(
            f"| {r['name']} | {'Yes' if r['bump'] else 'No'} | {r['ov']} -> {r['nv']} "
            f"| {'Yes' if r['other'] else 'No'} | {', '.join(r['other']) or '-'} |"
        )


def main(argv):
    parser = argparse.ArgumentParser(description="Compare savedsearches.conf between two content-update archives.")
    parser.add_argument("--previous-version", required=True, metavar="ARCHIVE", help="archive of the previous version")
    parser.add_argument("--new-version", required=True, metavar="ARCHIVE", help="archive of the new version")
    args = parser.parse_args(argv[1:])
    old_archive, new_archive = args.previous_version, args.new_version
    with tempfile.TemporaryDirectory() as tmp:
        confs = []
        for label, archive in (("old", old_archive), ("new", new_archive)):
            dest = os.path.join(tmp, label)
            os.mkdir(dest)
            try:
                extract(archive, dest)
                confs.append(parse_conf(find_conf(dest)))
            except (OSError, tarfile.TarError, ValueError) as e:
                print(f"error: {archive}: {e}", file=sys.stderr)
                return 2
    rows = compare(*confs)
    print_table(rows)
    no_other = sum(1 for r in rows if not r["other"])
    print(
        f"\n{len(rows)} changed stanzas; {sum(r['bump'] for r in rows)} with a version bump; "
        f"{no_other} with no changes beyond {METADATA_KEY}.",
        file=sys.stderr,
    )
    return 1 if no_other else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
