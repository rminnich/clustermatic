# $Id: beoboot-SuSE.spec,v 1.1 2004/10/26 18:49:53 mkdist Exp $
Summary: Clustermatic (BProc) Node Booting Utilities
Name: beoboot
Version: cm1.10
Release: 1
Copyright: GPL
Group: System Environment/Daemons
Source: beoboot-%{version}.tar.gz
Buildroot: /var/tmp/beoboot

BuildRequires: bproc-devel
Requires: bproc-devel

Packager: Erik Hendriks <hendriks@lanl.gov>

%define debug_package %{nil}
%ifarch i386 i486 i586 i686 alpha
%define havemonte 1
%else
%define havemonte 0
%endif


%description
Beoboot is a collection of programs, scripts and kernel modules which
allows one to easily boot nodes in a cluster.

%if %{havemonte}
%package -n km_kmonte
Summary: Two Kernel Monte Module
Group: System Environment/Libraries

%description -n km_kmonte
Beoboot is a collection of programs, scripts and kernel modules which
allows one to easily boot nodes in a cluster.

This package contains the source for the kernel modules.  It is
required to build the kernel modules during kernel build.
%endif

%prep
%setup

%build
make GM_HOME="$GM_HOME" \
     libdir=%{_libdir} includedir=%{_includedir} mandir=%{_mandir} \
     sysconfdir=%{_sysconfdir} bindir=%{_bindir} sbindir=%{_sbindir}

%install
rm -rf $RPM_BUILD_ROOT
make prefix=$RPM_BUILD_ROOT \
     libdir=%{_libdir} includedir=%{_includedir} mandir=%{_mandir} \
     sysconfdir=%{_sysconfdir} bindir=%{_bindir} sbindir=%{_sbindir} \
     install
mkdir -p $RPM_BUILD_ROOT/var/clustermatic

%if %{havemonte}
#--- Copy 2KM source...
DEST=$RPM_BUILD_ROOT/usr/src/kernel-modules/kmonte
mkdir -p $DEST

cp monte/monte.h  $DEST
cp monte/kmonte.c $DEST

cat <<EOF > $DEST/Makefile
EXTRA_CFLAGS:=-DPACKAGE_VERSION=%{version}
export EXTRA_CFLAGS
obj-m:=kmonte.o
modules:
	\$(MAKE) -C \$(KERNEL_SOURCE) KBUILD_EXTMOD=\`pwd\`
install:
	\$(MAKE) -C \$(KERNEL_SOURCE) KBUILD_EXTMOD=\`pwd\` modules_install
EOF
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%post
if [ -x /sbin/chkconfig ] ; then
    /sbin/chkconfig --add clustermatic
fi

%preun
if [ "$1" = "0" ]; then
    if [ -x /sbin/chkconfig ] ; then
	/sbin/chkconfig --del clustermatic
    fi
fi

%files
%defattr(-,root,root)
%config(noreplace) %{_sysconfdir}/clustermatic/config
%config(noreplace) %{_sysconfdir}/clustermatic/config.boot
%config(noreplace) %{_sysconfdir}/clustermatic/fstab
%config(noreplace) %{_sysconfdir}/clustermatic/node_up
%config(noreplace) %{_sysconfdir}/clustermatic/node_up.conf
%config(noreplace) %{_sysconfdir}/clustermatic/nsswitch.conf
%{_sysconfdir}/init.d/clustermatic
%{_bindir}/beoboot
%{_sbindir}/beoserv
%{_libdir}/beoboot
%{_includedir}/*
%{_mandir}/man5/*
%{_mandir}/man8/*
%dir /var/clustermatic

%if %{havemonte}
%files -n km_kmonte
%dir %attr (-,root,root) /usr/src/kernel-modules
%dir %attr (-,root,root) /usr/src/kernel-modules/kmonte
%attr (-,root,root) /usr/src/kernel-modules/kmonte/*
%endif

%changelog
* Mon Oct  4 2004 Erik Hendriks <hendriks@lanl.gov>
- Ported to SuSE's kernel module scheme.
* Tue Jun  3 2003 Erik Hendriks <hendriks@lanl.gov>
- Added line to include headers for plugin system.
* Tue Aug 13 2002 Erik Hendriks <hendriks@lanl.gov>
- Fixed up for removal of more old scripts.
- Moved Red Hat kernel build arguments into the make files.
* Wed Mar  6 2002 Erik Hendriks <hendriks@lanl.gov>
- Fixed requirements lines
* Wed Feb 20 2002 Erik Hendriks <hendriks@lanl.gov>
- Made some fixes to allow building w/o 2KM
* Thu Jan 23 2002 Erik Hendriks <hendriks@lanl.gov>
- Removed specific BProc version dependency.
- Separated out modules into a separate RPM.
* Thu Oct 19 2000 Erik Hendriks <hendriks@lanl.gov>
- Revamped for simpler beoboot which doesn't involve an internal linux kernel.
- "devel" RPM removed.
* Mon Jun 19 2000 Erik Hendriks <hendriks@lanl.gov>
- Initial version
