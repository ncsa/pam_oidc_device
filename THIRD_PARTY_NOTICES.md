# Third-Party Notices

`pam_oidc_device`'s own code is licensed under the [MIT License](LICENSE), but the module is
**not self-contained**: it vendors one small permissively licensed component and links against
a small set of well-known system libraries. This file is the **authoritative record** of every
third-party component, its license, its provenance, and how license compliance is verified.

The [README](README.md#third-party-components--licenses) carries a high-level summary; the
detail lives here. Compliance is enforced mechanically — see
[Compliance enforcement](#compliance-enforcement) and `scripts/check-licenses.sh`
(CI: `.github/workflows/license-audit.yml`).

---

## Components at a glance

| Component | Role | License | Where it lives |
| --- | --- | --- | --- |
| **Project Nayuki — QR Code generator (C edition)** | **Vendored / bundled** — compiled into the module | MIT | `third_party/qrcodegen/` |
| Linux-PAM (`pam`) | Runtime system library (PAM module ABI) | Linux-PAM license (3-clause BSD-style; alternatively GPL) | distribution package |
| cURL (`libcurl`) | Runtime system library (HTTPS transport) | curl license (MIT-style permission notice) | distribution package |
| json-c | Runtime system library (JSON parsing) | MIT | distribution package |
| OpenSSL (`openssl-libs`) | Runtime system library (Base64URL, SHA-256 for PKCE) | Apache-2.0 (OpenSSL 3.x; historical releases: dual OpenSSL license) | distribution package |
| CMocka (`libcmocka-devel`) | **Build/test only** — never shipped | Apache-2.0 (current upstream; 1.x distro releases: 3-clause BSD) | distribution package (CRB) |
| GitHub Actions `actions/checkout` | CI build tooling only (SHA-pinned, v7.0.1) | MIT | workflow files |

## License compatibility summary

* The project itself is **MIT**; the only code *bundled* in the repository is the vendored
  Nayuki QR encoder, which is also **MIT** — preserving its copyright and license notices
  (kept in the source file headers and re-verified by CI) fully satisfies its terms.
* All runtime libraries are **dynamically linked** and installed by the operating-system
  vendor as distribution packages; the binary packages declare them (RPM `Requires:`
  per-distro; DEB `Depends:` derived by `dpkg-shlibdeps` at build time — see
  `packaging/build-deb.sh`) and ship none of their source or binaries. Each
  license's redistribution terms are therefore the distribution's responsibility,
  not the module's.
* **No copyleft code (GPL / LGPL / AGPL) is vendored or linked into the module.** If a future
  component changes that, the license gate (`scripts/check-licenses.sh`, check L3) fails
  and the addition requires explicit review.

---

## 1. Project Nayuki — QR Code generator (C edition) — *MIT, vendored*

* **Copyright:** © Project Nayuki — `Copyright (c) Project Nayuki. (MIT License)`; the full MIT
  text is preserved in the file headers of `qrcodegen.c` / `qrcodegen.h`.
* **Purpose:** ISO/IEC 18004 QR encoding for the opt-in `[qr]` terminal sign-in feature
  (consumed by `src/qr.c`; only the private `static` API surface is used).
* **Provenance:** vendored from pinned upstream revisions
  (https://github.com/nayuki/QR-Code-generator, `c/qrcodegen.c` @
  `8329a7108fc22be3e1eec0a9f9318978579e3621`, `c/qrcodegen.h` @
  `f3705873ab6cc5e4ff64400d227dba2b5164ce74`; pinned 2026-11-08, SHA-256 digests and pin
  metadata in `third_party/qrcodegen/vendor-provenance.txt`).
* **Local deviations:** documented in `third_party/qrcodegen/AUTHORS` and captured in
  `third_party/qrcodegen/local-deviations.patch` (include guard, unconditional
  `#define testable static`, include ordering — plus clang-format; zero semantic effect).
* **Drift gate:** `vendor-audit.yml` → `scripts/check_qrcodegen_upstream.sh` re-verifies local
  integrity and token-level equivalence against the pinned upstream revision monthly and on
  every PR touching `third_party/**`.

## 2. Linux-PAM (`pam`) — *runtime*

* **Copyright:** © The Linux-PAM Project / Red Hat and contributors.
* **License:** the Linux-PAM permission notice — a 3-clause BSD-style license, with the file
  stating the product *may alternatively* be distributed under the GNU GPL. Distribution is
  handled by the OS vendor; the module merely links against `libpam`.
* **Used for:** the PAM module ABI (`pam_sm_authenticate`, `pam_sm_setcred`,
  `pam_get_user`, prompt/converse API) — `#include <security/pam_*.h>`.
* **Distribution package names:** the runtime/dev package is `pam` / `pam-devel`
  on both Red Hat EL and SUSE (openSUSE Leap / SLES).
* **Upstream:** https://github.com/linux-pam/linux-pam

## 3. cURL (`libcurl`) — *runtime*

* **Copyright:** © 1996–present Daniel Stenberg and many contributors.
* **License:** the "curl license" — a permissive MIT-style permission notice (copyright
  notice must appear in all copies).
* **Used for:** the HTTPS transport layer (`src/http.c`), with enforced TLS 1.2+ and mandatory
  peer/host certificate validation.
* **Distribution package names:** EL `libcurl` / `libcurl-devel`; SUSE (Leap / SLES)
  `libcurl4` / `libcurl-devel`.
* **Upstream:** https://curl.se / https://github.com/curl/curl

## 4. json-c — *runtime*

* **Copyright:** © 2009–2012 Eric Haszlakiewicz; © 2004–2005 Metaparadigm Pte Ltd.
* **License:** MIT.
* **Used for:** parsing all provider-supplied JSON (discovery document, device-authorization
  and token responses, UserInfo) in `src/http.c` and `src/jwt.c`.
* **Distribution package names:** EL `json-c` / `json-c-devel`; SUSE (Leap / SLES)
  `libjson-c5` / `libjson-c-devel`.
* **Upstream:** https://github.com/json-c/json-c

## 5. OpenSSL (`openssl-libs`) — *runtime*

* **Copyright:** © 1998–present The OpenSSL Project Authors; © 1995–1998 Eric A. Young,
  Tim J. Hudson.
* **License:** Apache License 2.0 (OpenSSL 3.x and later; earlier releases were dual-licensed
  under the traditional OpenSSL license). The EL8/9/10 distro packages supply the version in
  use.
* **Used for:** Base64URL decoding and SHA-256 (PKCE S256 challenge) in `src/jwt.c` /
  `src/pkce.c` (`libcrypto` only; TLS itself is performed by cURL).
* **Distribution package names:** EL `openssl-libs` / `openssl-devel`; SUSE (Leap / SLES)
  `openssl` / `libopenssl-devel`.
* **Upstream:** https://www.openssl.org / https://github.com/openssl/openssl

## 6. CMocka (`libcmocka-devel`) — *build/test only, not shipped*

* **Copyright:** © CMocka authors (Andreas Schneider et al.).
* **License:** Apache-2.0 per cmocka.org for current releases; 1.x-era distro packages were
  released under the 3-clause BSD license. Either way the license is permissive.
* **Used for:** the unit-test suite (`tests/test_suite.c`) — a `BuildRequires`-only dependency
  of the RPM; **never** included in the shipped `Requires:`. Binary package
  `libcmocka-devel` on both EL and SUSE.
* **Upstream:** https://cmocka.org / https://github.com/libcmocka/cmocka

## 7. CI build tooling

GitHub Actions (`actions/checkout` v7.0.1, MIT) is the only third-party software executed
during CI, and it is pinned by commit SHA in the workflow files. Lint/analysis tools
(clang-format, clang-tidy, cppcheck, flawfinder) run on the runner's own toolchain or pinned
pip versions and are not part of the distributed product.


---

## Compliance enforcement

| Gate | What it verifies | Where |
| --- | --- | --- |
| `scripts/check-licenses.sh` (`make check-licenses`) | L1: this file exists at the repo root. L2: every `third_party/*/` component carries license text, an `AUTHORS`/`NOTICE` attribution file, and a `vendor-provenance.txt` pin. L3: no copyleft (GPL/LGPL/AGPL) license text anywhere in `third_party/`. L4: every runtime dependency from **all** `Requires:` lines of the RPM spec (Red Hat EL and SUSE per-distro branches) is declared in this file. | local target; CI job `license-compliance` in `license-audit.yml` |
| GitHub dependency-graph audit (`scripts/audit-dependency-graph.py`) | Queries GitHub's dependency graph for every manifest/package GitHub has indexed for this repository and fails when any indexed package carries a license outside the permissive allowlist (MIT, ISC, BSD, Apache-2.0, zlib, …) or is not declared in this file. Today this pure-C/Make project has no manifest GitHub recognizes, so the gate passes with an INFO note and **activates automatically** the moment a manifest (e.g., `CMakeLists.txt`, `package.json`, `requirements.txt`) is added. | CI job `dependency-graph-audit` in `license-audit.yml` |

> [!NOTE]
> **Dependency-graph fallback mechanics.** The auditor queries the GraphQL
> `Repository.dependencyGraph` field first; that field is feature-gated per
> account, so on accounts without the supply-chain dependency-graph feature the
> query fails with the schema-level error `Field 'dependencyGraph' doesn't
> exist on type 'Repository'` and the auditor falls back to the REST
> `GET /repos/{owner}/{repo}/dependencies` endpoint. If that endpoint also
> returns 404 — as it does today, because the REST dependency-graph endpoints
> are feature-gated and this repository is private (no dependency-graph data
> exists to serve) — the job records an empty payload and the audit passes with
> an INFO no-op. When real data does arrive (a REST array of packages), the
> auditor cross-checks package names against this file (REST responses carry no
> license data).
| Vendor drift audit | The vendored QR encoder matches its pinned upstream revision (SHA-256 + token-level equivalence), and upstream has not advanced past the pin. | CI job in `vendor-audit.yml` |

This notices file is shipped in the RPM **source** tarball alongside `LICENSE` so that anyone
rebuilding the source package sees the complete third-party record.

## Adding a new third-party component

1. **License screen first:** only permissive licenses (MIT, BSD, ISC, Apache-2.0, zlib, curl)
   are acceptable. GPL/LGPL/AGPL components are rejected by `scripts/check-licenses.sh` (L3)
   and require explicit legal review before any exception.
2. **Vendored code** goes into `third_party/<name>/` and must include: the license text
   (a `LICENSE`/`COPYING` file *or* the upstream license header kept in every source file),
   an `AUTHORS` or `NOTICE` attribution file, and a `vendor-provenance.txt`
   (upstream repo, pinned revision, pin date, local SHA-256 digests, deviation patch).
   Add a periodic upstream-drift audit the way `scripts/check_qrcodegen_upstream.sh` does.
3. **System dependencies:** declare them in the RPM spec (`Requires:` / `BuildRequires:`) and
   add an entry to the [Components at a glance](#components-at-a-glance) table plus a detail
   section above (check L4 fails if a `Requires:` entry is missing from this file).
4. Run `make check-licenses` locally; `license-audit.yml` re-verifies everything in CI.
