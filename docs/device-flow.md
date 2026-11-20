# The Device Authorization Grant (RFC 8628), in Detail

Background for `pam_oidc_device`: what the OAuth 2.0 Device Authorization Grant is, where you
have already used it, and how the pattern maps onto a Linux PAM module. For the module-specific
sequence (with diagram), see [How It Works in the README](../README.md#how-it-works).

## Table of Contents

* [The Flow](#the-flow)
* [You Have Used This Flow Already](#you-have-used-this-flow-already)
* [How This Maps to a Linux PAM Module](#how-this-maps-to-a-linux-pam-module)
* [Related](#related)

---

## The Flow

The **OAuth 2.0 Device Authorization Grant** ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) is the standard authorization flow for **limited-input clients** — systems with no comfortable place to type a username and password, because the screen is small, the keyboard is absent, or a local browser can't be trusted with credentials.

The grant splits sign-in across two devices:

1. The limited-input client asks the identity provider for a short, single-use, time-limited **user code** plus a **verification URL**.
2. It displays both in whatever interface it has.
3. On *any other* device with a browser, the user opens the URL, signs in to their account, and enters the code to approve the request.
4. The original client **polls** the provider until the code is approved (or expires), and only then receives its credentials.

No password ever travels through the limited-input client — the only secret it handles is the short, expiring user code.

---

## You Have Used This Flow Already

It is the pattern behind:

* **Smart-TV and streaming apps** — the familiar "go to `sign.example.com` and enter code `XXXX-1234`";
* **Game consoles and smart/IoT devices** — pairing hardware with your account without a full keyboard;
* **Headless or remote systems** — servers, lab equipment, and appliances where a local web login is awkward or undesirable.

---

## How This Maps to a Linux PAM Module

A login host reached over SSH is the same kind of limited-input client: there is no browser on the host, and the terminal is exactly where you do *not* want to type a password. `pam_oidc_device` plays the RFC 8628 *device client* role inside the PAM authentication stack — the SSH session shows the verification prompt, while the actual sign-in and approval happen on a second device, in a browser, against your identity provider.

Because the module is a standard PAM module, the same sign-in extends to other PAM-managed services — see [Beyond SSH: Other PAM Services](../README.md#beyond-ssh-other-pam-services).

---

## Related

* [Getting Started](getting-started.md) — deployment walkthrough
* [Provider Examples & Discovery](../examples/README.md) — endpoints, PKCE support, complete config templates per identity provider
* [Threat Model & Security Architecture](threat-model.md) — trust boundaries and the device-code phishing discussion
