Summary: glibc nss routines for BProc
Name: beonss
Version: cm1.2
Release: 2
Source:	beonss-%{version}.tar.gz
Copyright: GPL
Group: System Environment/Libraries
BuildRequires: bproc-devel
Buildroot: /var/tmp/beonss-root
Requires: bproc-libs
Requires: glibc

%define _prefix %{nil}
%define debug_package %{nil}

%define build32 0
%define build64 0

%ifarch i386 i486 i586 i686 athlon ppc
%define build32 1
%define _lib32dir /lib
%define _lib64dir /lib64
%endif
%ifarch x86_64 ppc64
%define build32 1
%define build64 1
%define _lib32dir /lib
%define _lib64dir /lib64
%endif

%description
glibc nss routines for BProc.  beonss uses BProc to translate host
names such as "n1000" to the appropriate address information for the
node.

%package 32bit
Summary: glibc nss routines for BProc
Group: System Environment/Libraries

%description 32bit
glibc nss routines for BProc.  beonss uses BProc to translate host
names such as "n1000" to the appropriate address information for the
node.


%prep
%setup -q

%build
rm -rf $RPM_BUILD_ROOT

%if %{build32}
make CC="gcc -m32"
mkdir -p $RPM_BUILD_ROOT/%{_lib32dir}
install -m 755 libnss_bproc.so.2 $RPM_BUILD_ROOT/%{_lib32dir}
make clean
%endif
%if %{build64}
make CC="gcc -m64"
mkdir -p $RPM_BUILD_ROOT/%{_lib64dir}
install -m 755 libnss_bproc.so.2 $RPM_BUILD_ROOT/%{_lib64dir}
make clean
%endif

%install


%post
/sbin/ldconfig
cat /etc/nsswitch.conf | awk '{ if((/^hosts:/) && !(/bproc/)) { print("#" $0); printf("hosts:\t"); for(x=2;x<=NF;x++) { if($x == "dns") printf(" bproc dns"); else printf(" " $x); } print(""); } else print($0);}' > /tmp/nsswitch.conf.bproc && mv -f /etc/nsswitch.conf /etc/nsswitch.conf.bak && mv -f /tmp/nsswitch.conf.bproc /etc/nsswitch.conf

%postun -p /sbin/ldconfig

%clean

%if %{build64}
# 64 bit case ---------------------------------------------------
%files
%defattr(-,root,root)
%doc README COPYING
%{_lib64dir}/libnss_bproc.so.2

%if %{build32}
# Mixed mode case
%files 32bit
%defattr(-,root,root)
%doc README COPYING
%{_lib32dir}/libnss_bproc.so.2
%endif

%else
# 32 bit only case ----------------------------------------------
%files
%defattr(-,root,root)
%doc README COPYING
%{_lib32dir}/libnss_bproc.so.2
%endif
