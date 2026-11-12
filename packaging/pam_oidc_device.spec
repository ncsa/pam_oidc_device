# Fallback defaults if built directly via rpmbuild without Makefile defines
%{!?mod_name:    %global mod_name pam_oidc_device}
%{!?mod_version: %global mod_version 0.3.1}
%{!?mod_summary: %global mod_summary PAM authentication module for OAuth 2.0 Device Authorization Grant}

Name:           %{mod_name}
Version:        %{mod_version}
Release:        1%{?dist}
Summary:        %{mod_summary}

License:        MIT
URL:            https://github.com/ncsa/pam_oidc_device
Source0:        %{name}-%{version}.tar.gz

# Binary package names differ between Red Hat EL and SUSE (openSUSE Leap /
# SLES). The SUSE names below are verified against openSUSE 16.0-era builds
# (libcurl4-*/libjson-c5-*/openssl-*/pam-*/libcmocka-devel-*-160000.*) and
# exercised by the CI "distro-build" job (SUSE: openSUSE Leap 16.0 in
# .github/workflows/distro-build.yml):
#   EL (RHEL/Rocky):      pam, pam-devel, libcurl, libcurl-devel,
#                         json-c, json-c-devel, openssl-libs, openssl-devel
#   SUSE (Leap/SLES):     pam, pam-devel, libcurl4, libcurl-devel,
#                         libjson-c5, libjson-c-devel, openssl, libopenssl-devel
# (libcmocka-devel is the cmocka build-dep name on both families.)
%if 0%{?suse_version}
BuildRequires:  gcc, make, pam-devel, libcurl-devel, libjson-c-devel, libopenssl-devel, libcmocka-devel
Requires:       pam, libcurl4, libjson-c5, openssl
%else
BuildRequires:  gcc, pam-devel, libcurl-devel, json-c-devel, openssl-devel, libcmocka-devel, make
Requires:       pam, libcurl, json-c, openssl-libs
%endif

# Disable separate debugsource package creation to prevent empty file list errors
%undefine _debugsource_packages

%description
A native Linux PAM authentication module that uses the OAuth 2.0 Device
Authorization Grant (RFC 8628) and binds the resulting provider identity
to the requested local account. It can be composed with other PAM
authentication modules for step-up or multi-factor authentication.

%prep
%setup -q

%build
# Build with the Makefile's own default flags instead of distro macros:
# the Makefile encodes the project's documented flag bar (-fstack-protector-strong,
# -D_FORTIFY_SOURCE=2, the full -Wall/-Wextra warning set, -O2 -g) and links
# with -Wl,-z,relro,-z,now. The %{build_cflags}/%{build_ldflags} macros are
# distribution-specific and cannot be relied on: %build_ldflags is undefined
# on openSUSE Leap 16.0, where rpmbuild leaves the literal "%{build_ldflags}"
# in the link line and the build fails with "cannot find %{build_ldflags}".
make

%check
make test

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot} PAM_DIR=%{_libdir}/security CONFIG_DIR=%{_sysconfdir}
# Ship the third-party QR encoder attribution (Project Nayuki, MIT) with the
# package; the full license text also lives in the encoder file headers.
install -d %{buildroot}%{_docdir}/%{name}/third_party
install -m 0644 third_party/qrcodegen/AUTHORS %{buildroot}%{_docdir}/%{name}/third_party/AUTHORS

%files
%license LICENSE
%license %{_docdir}/%{name}/third_party/AUTHORS
%doc README.md CHANGELOG.md SECURITY.md
%config(noreplace) %attr(0600, root, root) %{_sysconfdir}/%{name}.conf
%attr(0755, root, root) %{_libdir}/security/%{name}.so

%changelog
