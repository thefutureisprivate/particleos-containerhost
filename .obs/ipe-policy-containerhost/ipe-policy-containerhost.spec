# needssslcertforbuild
# needsrootforbuild

%if 0%{?fedora}
%global debug_package %{nil}
%endif

Name:           ipe-policy-containerhost
Version:        0.0.2
Release:        0
Summary:        Signed IPE policy for the ParticleOS gVisor container host
License:        GPL-2.0-or-later
Source0:        ipe-policy
Source1:        extract-ipe-signature.py
BuildArch:      noarch
BuildRequires:  cpio python3
BuildRequires:  systemd
Provides:       ipe-policy = %{version}-%{release}
Obsoletes:      ipe-policy < %{version}

%description
Signed IPE policy adapted for a dm-verity ParticleOS host that runs gVisor's
systrap platform while retaining fail-closed checks for kernel-fed objects.

%prep

%build

%install
install -d %{buildroot}/etc/ipe
install -d hashes

if [ ! -f %{_sourcedir}/hashes.cpio.rsasign.sig ]; then
    install -m0644 %{SOURCE0} hashes/ipe-policy
    pushd hashes
    find . -type f -print0 | sort -z | cpio --null -H newc -o >%{_sourcedir}/../OTHER/hashes.cpio.rsasign
    popd
    install -m0644 %{SOURCE0} %{_sourcedir}/../OTHER/ipe-policy
    install -m0644 %{SOURCE1} %{_sourcedir}/../OTHER/extract-ipe-signature.py
    install -m0644 %{_sourcedir}/ipe-policy-containerhost.spec %{_sourcedir}/../OTHER/ipe-policy-containerhost.spec
    touch %{buildroot}/etc/ipe/ipe-policy.p7b
else
    /usr/bin/python3 %{SOURCE1} %{_sourcedir}/hashes.cpio.rsasign.sig hashes
    PATH=/usr/lib/systemd/:$PATH systemd-keyutil \
        --certificate %{_sourcedir}/_projectcert.crt \
        --output %{buildroot}/etc/ipe/ipe-policy.p7b \
        --content %{SOURCE0} --signature hashes/ipe-policy.sig pkcs7
fi

%files
%dir /etc/ipe
/etc/ipe/ipe-policy.p7b

%changelog
* Tue Aug 18 2026 The future is private. <contact@thefutureisprivate.dev>
- Initial container-host policy
