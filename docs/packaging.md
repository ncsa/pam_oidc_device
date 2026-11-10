# Building RPM & DEB Packages

How to build distributable `pam_oidc_device` packages. Day-to-day deployment
can also use `make && sudo make install` — see the
[Getting Started guide](getting-started.md) §2.

## Building RPM Packages (EL8 / EL9 / EL10 / SUSE)

Building RPM packages locally requires `libcmocka-devel` (on EL, available in the CRB / CodeReady Builder repository):

```bash
# Enable CRB repository (EL only)
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --set-enabled crb

# Install build dependencies & compile RPM
sudo dnf builddep -y packaging/pam_oidc_device.spec
make rpm
```

The resulting packages will be generated under `rpmbuild/RPMS/x86_64/`:

```bash
sudo dnf localinstall -y rpmbuild/RPMS/x86_64/pam_oidc_device-0.3.0-1.el9.x86_64.rpm
```

The same `make rpm` target works on **SUSE** (openSUSE Leap / SLES) — the spec's
`%if 0%{?suse_version}` branch selects the SUSE binary package names
(`pam-devel`, `libcurl-devel`, `libjson-c-devel`, `libopenssl-devel`,
`libcmocka-devel` at build time; `pam`, `libcurl4`, `libjson-c5`, `openssl` at
runtime):

```bash
# openSUSE Leap / SLES
sudo zypper install -y gcc make rpm-build pam-devel libcurl-devel libjson-c-devel libopenssl-devel libcmocka-devel python3
make rpm
sudo zypper install rpmbuild/RPMS/x86_64/pam_oidc_device-*.rpm
```

## Building DEB Packages (Debian / Ubuntu)

`make deb` hand-crafts a binary `.deb` with `dpkg-deb` — no debhelper /
`dpkg-buildpackage` toolchain needed. `dpkg-shlibdeps` derives
distribution-correct runtime `Depends` from the built module, the module is
installed to `/lib/<multiarch>/security` (the PAM module directory Debian /
Ubuntu libpam searches), and `/etc/pam_oidc_device.conf` ships as a `0600`
conffile:

```bash
# Debian 13 / Ubuntu 26.04 LTS
sudo apt-get install -y build-essential dpkg-dev python3 \
  libpam0g-dev libcurl4-openssl-dev libjson-c-dev libcmocka-dev libssl-dev
make deb
sudo dpkg -i build/pam-oidc-device_0.3.0_$(dpkg --print-architecture).deb
```

The output `.deb` is generated under `build/` (e.g.
`build/pam-oidc-device_0.3.0_amd64.deb`). The package is named
`pam-oidc-device` (dash form) because Debian package names may not contain
underscores; the installed files keep the module name
(`pam_oidc_device.so`, `/etc/pam_oidc_device.conf`).

> [!NOTE]
> **CI coverage:** EL8/EL9/EL10 RPM builds run in the `rpm-build` job of
> `.github/workflows/build.yml`; SUSE (openSUSE Leap 16.0), Debian 13, and
> Ubuntu 26.04 LTS native builds + package installs run in the `distro-build`
> jobs of `.github/workflows/distro-build.yml` on every push/PR to `main`.
