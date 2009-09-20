# $Id: beoboot.spec,v 1.28 2004/11/03 22:47:05 mkdist Exp $
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
%define ARCH %(echo %{_target_cpu} | sed -e s/i.86/i386/)

%description
Beoboot is a collection of programs and scripts which allows one to
easily boot nodes in a cluster.

%prep
%setup

%build
#####################################################################
#### HORRIBLE HACK to get this shit built on yellowdog w/32 bit bfd lib
%ifarch ppc64
make ARCH=ppc kver
%endif
#####################################################################

make ARCH=%{ARCH} LINUX= GM_HOME="$GM_HOME" prefix=$RPM_BUILD_ROOT \
     libdir=%{_libdir} includedir=%{_includedir} mandir=%{_mandir} \
     sysconfdir=%{_sysconfdir} bindir=%{_bindir} sbindir=%{_sbindir}

%install
rm -rf $RPM_BUILD_ROOT
make ARCH=%{ARCH} LINUX= GM_HOME="$GM_HOME" prefix=$RPM_BUILD_ROOT \
     libdir=%{_libdir} includedir=%{_includedir} mandir=%{_mandir} \
     sysconfdir=%{_sysconfdir} bindir=%{_bindir} sbindir=%{_sbindir} \
     install
mkdir -p $RPM_BUILD_ROOT/var/clustermatic

# This one is coming from the BProc package now..
rm $RPM_BUILD_ROOT/etc/clustermatic/config

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
# I moved this one to the bproc package....
#%config(noreplace) %{_sysconfdir}/clustermatic/config
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
%dir /var/clustermatic
%{_mandir}/man5/*
%{_mandir}/man8/*

%changelog
* Tue Nov  3 2004 Erik Hendriks <hendriks@lanl.gov>
- Removed module building stuff.
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
