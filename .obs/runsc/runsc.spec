# SPDX-License-Identifier: Apache-2.0
Name:           runsc
Version:        20260810.0
Release:        0
Summary:        gVisor OCI sandbox runtime
License:        Apache-2.0
URL:            https://gvisor.dev/
Source0:        _service:download_url:gvisor.tar.bz2
Source1:        _service:download_url:LICENSE.gvisor
ExclusiveArch:  x86_64

%description
Official, release-pinned gVisor runsc binaries for rootful OCI workloads. The
systrap platform is selected by the ParticleOS host configuration.

%prep
%setup -q -c -T
tar -xjf %{SOURCE0}
cp %{SOURCE1} LICENSE

%build

%install
install -Dpm0755 runsc %{buildroot}%{_libexecdir}/gvisor/runsc
install -d -m0755 %{buildroot}%{_libexecdir}/gvisor/gvisor-bin
install -m0755 gvisor-bin/* %{buildroot}%{_libexecdir}/gvisor/gvisor-bin/
install -d -m0755 %{buildroot}%{_bindir}
ln -s %{_libexecdir}/gvisor/runsc %{buildroot}%{_bindir}/runsc

%check
test "$(%{buildroot}%{_libexecdir}/gvisor/runsc --version | sed -n 's/^runsc version //p')" = "release-20260810.0"

%files
%license LICENSE
%{_bindir}/runsc
%dir %{_libexecdir}/gvisor
%{_libexecdir}/gvisor/runsc
%{_libexecdir}/gvisor/gvisor-bin/

%changelog
