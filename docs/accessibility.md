# Accessibility

This project's documentation and terminal user experience are built to
[WCAG 2.1 Level AA](https://www.w3.org/TR/WCAG21/) — the shared technical
baseline of the three accessibility mandates governing NCSA / University of
Illinois public-facing content:

* **Illinois Information Technology Accessibility Act (IITAA 2.1,
  30 ILCS 587):** applies to Illinois state agencies and state-supported
  universities (including the University of Illinois), requiring digital
  content and documentation to meet WCAG 2.1 Level AA.
* **ADA Title II Web Accessibility Rule (28 CFR Part 35):** requires public
  universities and state entities to conform public web content and
  documentation to WCAG 2.1 Level AA (effective April 2026).
* **Section 508 of the Rehabilitation Act (29 U.S.C. § 794d):** applies to
  federally funded research, software, and documentation (e.g., NSF-supported
  NCSA projects) and incorporates the WCAG Level AA standards (36 CFR
  Part 1194, per the Access Board's 2017 final rule).

---

## In Concrete Terms

* **Documentation:** The README and the guides under `docs/` use semantic
  heading structure, data tables with header rows, text alternatives for every
  image, no information conveyed by color alone, and content that remains fully
  navigable by keyboard and screen reader in rendered form.
* **Terminal sign-in experience:** The authentication prompt is text-first and
  screen-reader friendly. The sign-in URL and user code are *always* presented
  as plain, selectable terminal text — never image-only — and no prompt
  information depends on color. The interaction is entirely keyboard-driven:
  **Enter** begins waiting for your approval, and **Ctrl-C** aborts the attempt
  at any point (the login is denied — `PAM_ABORT`). There are no time-limited
  interactions that cannot be cancelled; the user-code lifetime itself is set by
  your identity provider (`expires_in`), and idle time at the confirmation
  prompt counts against it (see [Getting Started, §4](getting-started.md#4-openssh-server-setup-etcsshsshd_config)).
  Failed attempts are never silent: the module delivers a plain-text, actionable
  explanation to the terminal (for example, the sign-in code expired, the identity
  provider service is unavailable, or the account is denied) so users are not left
  with an unexplained "permission denied" (WCAG 3.3.1 *Error Identification*).
  Delivery is best-effort, and detailed causes remain in the audit log only
  (see [Getting Started, §7](getting-started.md#7-logging--auditing)).
* **QR sign-in (opt-in):** The `[qr]` terminal QR code is strictly
  *supplemental* (WCAG 1.1.1 *Non-text Content*): authentication never depends
  on it, it is off by default, and `style = ascii` renders it in plain ASCII
  for minimal fonts. Screen-reader and low-vision users should rely on the
  text prompt, which is displayed in all cases.

---

## Reporting Barriers

If you encounter an accessibility barrier in this documentation or in the
module's terminal experience, please [open an issue](https://github.com/ncsa/pam_oidc_device/issues)
describing the barrier; accessibility reports are triaged with priority.
