#!/usr/bin/env python3
# Copyright (c) Arduino SA
# SPDX-License-Identifier: BSD-3-Clause

# Compare two SPDX JSON SBOMs and produce a delta report showing packages
# added, removed, or changed between a base and a target image.
#
# Usage:
#     sbom-delta.py [--format json|csv|markdown] base.spdx.json target.spdx.json

import json
import argparse


def load_packages(spdx_json_path):
    """Load an SPDX JSON file and return a dict of {name: {version, license}}."""
    with open(spdx_json_path, 'r') as f:
        data = json.load(f)

    packages = {}
    for pkg in data.get("packages", []):
        name = pkg.get("name", "")
        # skip the document-level package (SPDX root element)
        spdx_id = pkg.get("SPDXID", "")
        if spdx_id == "SPDXRef-DOCUMENT" or not name:
            continue

        version = pkg.get("versionInfo", "")
        license_declared = pkg.get("licenseDeclared", "NOASSERTION")

        packages[name] = {
            "version": version,
            "license": license_declared,
        }

    return packages


def compute_delta(base_pkgs, target_pkgs):
    """Compute structured delta between base and target package sets."""
    base_names = set(base_pkgs.keys())
    target_names = set(target_pkgs.keys())

    added = {n: target_pkgs[n] for n in sorted(target_names - base_names)}
    removed = {n: base_pkgs[n] for n in sorted(base_names - target_names)}

    version_changed = {}
    license_changed = {}
    for name in sorted(base_names & target_names):
        bv = base_pkgs[name]["version"]
        tv = target_pkgs[name]["version"]
        bl = base_pkgs[name]["license"]
        tl = target_pkgs[name]["license"]
        if bv != tv:
            version_changed[name] = {
                "base_version": bv,
                "target_version": tv,
            }
        if bl != tl:
            license_changed[name] = {
                "base_license": bl,
                "target_license": tl,
            }

    return {
        "summary": {
            "base_count": len(base_pkgs),
            "target_count": len(target_pkgs),
            "added": len(added),
            "removed": len(removed),
            "version_changed": len(version_changed),
            "license_changed": len(license_changed),
        },
        "added": added,
        "removed": removed,
        "version_changed": version_changed,
        "license_changed": license_changed,
    }


def format_json(delta):
    return json.dumps(delta, indent=2)


def format_csv(delta):
    lines = ["action,package,version_base,version_target,license"]
    for name, info in delta["added"].items():
        lines.append(f"added,{name},,{info['version']},{info['license']}")
    for name, info in delta["removed"].items():
        lines.append(f"removed,{name},{info['version']},,{info['license']}")
    for name, info in delta["version_changed"].items():
        lines.append(
            f"version_changed,{name},"
            f"{info['base_version']},{info['target_version']},")
    for name, info in delta["license_changed"].items():
        lines.append(
            f"license_changed,{name},,"
            f",{info['base_license']} -> {info['target_license']}")
    return "\n".join(lines)


def format_markdown(delta):
    lines = []
    s = delta["summary"]
    lines.append("## SBOM Delta: main vs arduino\n")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Base (main) packages | {s['base_count']} |")
    lines.append(f"| Target (arduino) packages | {s['target_count']} |")
    lines.append(f"| Added in arduino | {s['added']} |")
    lines.append(f"| Removed from main | {s['removed']} |")
    lines.append(f"| Version changed | {s['version_changed']} |")
    lines.append(f"| License changed | {s['license_changed']} |")
    lines.append("")

    if delta["added"]:
        lines.append("### Packages added in arduino\n")
        lines.append("| Package | Version | License |")
        lines.append("|---------|---------|---------|")
        for name, info in delta["added"].items():
            lines.append(f"| {name} | {info['version']} | {info['license']} |")
        lines.append("")

    if delta["removed"]:
        lines.append("### Packages removed (in main but not arduino)\n")
        lines.append("| Package | Version | License |")
        lines.append("|---------|---------|---------|")
        for name, info in delta["removed"].items():
            lines.append(f"| {name} | {info['version']} | {info['license']} |")
        lines.append("")

    if delta["version_changed"]:
        lines.append("### Version changes\n")
        lines.append("| Package | Main | Arduino |")
        lines.append("|---------|------|---------|")
        for name, info in delta["version_changed"].items():
            lines.append(
                f"| {name} | {info['base_version']}"
                f" | {info['target_version']} |")
        lines.append("")

    if delta["license_changed"]:
        lines.append("### License changes\n")
        lines.append("| Package | Main | Arduino |")
        lines.append("|---------|------|---------|")
        for name, info in delta["license_changed"].items():
            lines.append(
                f"| {name} | {info['base_license']}"
                f" | {info['target_license']} |")

    return "\n".join(lines)


FORMATTERS = {
    "json": format_json,
    "csv": format_csv,
    "markdown": format_markdown,
}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Compare two SPDX JSON SBOMs and produce a delta report.")
    parser.add_argument("base", help="Path to the base (main) SPDX JSON file")
    parser.add_argument("target",
                        help="Path to the target (arduino) SPDX JSON file")
    parser.add_argument("--format", choices=FORMATTERS.keys(), default="json",
                        help="Output format (default: json)")
    args = parser.parse_args()

    base_pkgs = load_packages(args.base)
    target_pkgs = load_packages(args.target)
    delta = compute_delta(base_pkgs, target_pkgs)
    print(FORMATTERS[args.format](delta))
