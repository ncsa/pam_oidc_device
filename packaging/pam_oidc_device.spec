# Fallback defaults if built directly via rpmbuild without Makefile defines
%{!?mod_name:    %global mod_name pam_oidc_device}
%{!?mod_version: %global mod_version 0.1.0}
%{!?mod_summary: %global mod_summary PAM authentication module for OAuth 2.0 Device Authorization Grant}

Name:           %{mod_name}
Version:        %{mod_version}
Release:        1%{?dist}
Summary:        %{mod_summary}

License:        MIT
URL:            https://github.com/ncsa/pam_oidc_device
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc, pam-devel, libcurl-devel, json-c-devel, openssl-devel, libcmocka-devel, make
Requires:       pam, libcurl, json-c, openssl-libs

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
make CFLAGS="%{build_cflags}" LDFLAGS="%{build_ldflags} -Wl,-z,relro,-z,now"

%check
make test

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot} PAM_DIR=%{_libdir}/security CONFIG_DIR=%{_sysconfdir}

%files
%license LICENSE
%doc README.md CHANGELOG.md SECURITY.md
%config(noreplace) %attr(0600, root, root) %{_sysconfdir}/%{name}.conf
%attr(0755, root, root) %{_libdir}/security/%{name}.so

%changelog
