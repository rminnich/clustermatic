Summary: 2 Kernel Monte
Name: monte
Version: cm1.10
Release: 1
Copyright: GPL
Group: System Environment/Drivers
Source0: monte-%{version}.tar.gz

Packager: Erik Arjan Hendriks <hendriks@lanl.gov>
Buildroot: /tmp/monte

%description
2 Kernel Monte is a kernel module which allows Linux to load another
Linux kernel image into RAM and restart the machine from that kernel.
The loader supports initial ramdisks and passing arbitrary kernel
command line parameters to the new kernel.

%prep
%setup

%build
make
sgml2txt monte.sgml

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/lib/modules/`uname -r`/misc
mkdir -p $RPM_BUILD_ROOT/sbin
mkdir -p $RPM_BUILD_ROOT/usr/man/man8

install -m 755 monte    $RPM_BUILD_ROOT/sbin/monte
install -m 644 monte.8  $RPM_BUILD_ROOT/usr/man/man8
install -m 644 kmonte.o $RPM_BUILD_ROOT/lib/modules/`uname -r`/misc

%post
[ -x /sbin/depmod ] && /sbin/depmod -a

%files
%defattr(-,root,root)
%doc monte.txt
/sbin/monte
/usr/man/man8/monte.8
/lib/modules
