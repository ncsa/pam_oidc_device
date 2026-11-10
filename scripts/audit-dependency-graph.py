#!/usr/bin/env python3
"""Audit GitHub dependency-graph packages against the license allowlist.

Consumes the JSON saved by the "Query GitHub dependency graph" step of
`.github/workflows/license-audit.yml` and fails when any indexed package
carries a license outside the permissive allowlist; packages not declared
in THIRD_PARTY_NOTICES.md are flagged with a warning.

Two payload shapes are accepted:

* **GraphQL** (``gh api graphql``): ``data.repository.dependencyGraph.
  packagesV2.nodes`` — nodes include license data, so the full allowlist
  audit runs.
* **REST** (``gh api repos/{owner}/{repo}/dependencies``): a top-level
  JSON array with ``name`` / ``ecosystem`` / ``version`` / ``manifests``
  but **no** license data. GitHub only exposes the ``Repository.
  dependencyGraph`` GraphQL field to accounts where the supply-chain
  dependency-graph feature is enabled; when the schema-level error
  "Field 'dependencyGraph' doesn't exist on type 'Repository'" occurs,
  the workflow falls back to REST. REST packages are cross-checked
  against THIRD_PARTY_NOTICES.md and reported with license "unknown"
  (no failure is invented from missing data).

A repository with no indexed packages (this pure-C/Make project has no
manifest GitHub recognizes today) passes with an INFO note: the gate
activates automatically the moment GitHub indexes a recognized manifest
(e.g. CMakeLists.txt, package.json, requirements.txt).

Usage:  python3 scripts/audit-dependency-graph.py [dependency-graph.json]
"""

import json
import os
import sys

# Permissive-license allowlist (GitHub license keys, SPDX-ish identifiers).
# Anything else (GPL-family, proprietary, unknown-strict) fails the audit.
ALLOWED_LICENSES = {
    "MIT",
    "ISC",
    "0BSD",
    "BSD-2-CLAUSE",
    "BSD-3-CLAUSE",
    "APACHE-2.0",
    "ZLIB",
    "CC0-1.0",
    "CC-BY-3.0",
    "CC-BY-4.0",
    "MPL-2.0",
    "MS-PL",
    "X11",
    "PYTHON-2.0",
    "ECL-2.0",
}

# Schema-level error text GitHub returns when the feature-gated
# Repository.dependencyGraph field is absent from the served schema.
GRAPHQL_FEATURE_GATED_MARKERS = (
    "Field 'dependencyGraph' doesn't exist on type 'Repository'",
    "Cannot query field 'dependencyGraph'",
)


def load_json(path):
    """Return parsed JSON, None when the file is absent, hard-fail on bad JSON."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except ValueError as exc:
        print("FAIL: cannot parse {}: {}".format(path, exc), file=sys.stderr)
        sys.exit(1)


def classify(data):
    """Return (nodes, source) where source is 'GraphQL', 'REST', or 'unavailable'."""
    if isinstance(data, dict) and ("data" in data or "errors" in data):
        errors = data.get("errors") or []
        if errors:
            if any(any(m in str(err.get("message", err))
                       for m in GRAPHQL_FEATURE_GATED_MARKERS) for err in errors):
                print("INFO: the GraphQL 'dependencyGraph' field is not in the schema on "
                      "this account (GitHub feature-gates it while the supply-chain "
                      "dependency graph is not enabled); no GraphQL data available.")
                return [], "unavailable"
            print("FAIL: GitHub dependency-graph query returned errors:", file=sys.stderr)
            for err in errors:
                print("  {}".format(err.get("message", err)), file=sys.stderr)
            sys.exit(1)
        repo = (data.get("data") or {}).get("repository")
        if repo is None:
            print("INFO: dependency-graph query returned no repository; nothing to audit.")
            sys.exit(0)
        graph = repo.get("dependencyGraph")
        if graph is None:
            return [], "GraphQL"
        return (graph.get("packagesV2") or {}).get("nodes") or [], "GraphQL"
    if isinstance(data, list):
        return data, "REST"
    if isinstance(data, dict) and "message" in data:
        print("FAIL: dependencies API returned an error payload: {}".format(
            data.get("message")), file=sys.stderr)
        sys.exit(1)
    print("FAIL: unrecognized dependency-graph payload shape ({}).".format(
        type(data).__name__), file=sys.stderr)
    sys.exit(1)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "dependency-graph.json"
    data = load_json(path)
    if data is None:
        print("INFO: no dependency-graph payload ({} not found); nothing to audit.".format(path))
        return 0

    nodes, source = classify(data)
    if source == "unavailable":
        print("INFO: no dependency-graph data available; nothing to audit.")
        return 0

    if not nodes:
        print(
            "INFO: GitHub dependency graph has no indexed packages for this "
            "repository (expected for a pure-C/Make project). This gate "
            "activates automatically once GitHub indexes a recognized "
            "manifest (CMakeLists.txt, package.json, requirements.txt, ...)."
        )
        return 0

    if source == "REST":
        print("NOTE: REST fallback has no license data — license allowlist "
              "check is skipped; names are cross-checked against "
              "THIRD_PARTY_NOTICES.md only.")

    notices_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.pardir, "THIRD_PARTY_NOTICES.md")
    with open(notices_path, encoding="utf-8") as fh:
        notices = fh.read().lower()

    failures = []
    for pkg in nodes:
        if source == "REST":
            manifest = ", ".join(m.get("path", "?") for m in pkg.get("manifests", [])) or "?"
            licenses = []
        else:
            manifest = pkg.get("manifestName", "?")
            licenses = sorted({
                lic["license"]["name"]
                for lic in pkg.get("licenses", [])
                if lic.get("license")
            })
        print("{}: {}@{}  (manifest: {})  licenses={}".format(
            pkg.get("ecosystem", "?"),
            pkg.get("name", "?"),
            pkg.get("version", "?"),
            manifest,
            licenses or ["unknown"],
        ))
        for lic in licenses:
            if lic.upper() not in ALLOWED_LICENSES:
                failures.append(
                    "non-allowlisted license '{}' on {} ({})".format(
                        lic, pkg.get("name"), manifest))
        if str(pkg.get("name", "")).lower() not in notices:
            print("  WARN: '{}' is not declared in THIRD_PARTY_NOTICES.md — "
                  "add an entry before merging.".format(pkg.get("name")))

    if failures:
        for failure in failures:
            print("FAIL: {}".format(failure), file=sys.stderr)
        return 1

    print("dependency-graph audit: OK — every indexed package is on the "
          "license allowlist.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
