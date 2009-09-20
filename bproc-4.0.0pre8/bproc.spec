#
# Erik Hendriks <erik@hendriks.cx>
#
# Copyright (C) 2000-2001 Erik Hendriks
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# $Id: bproc.spec,v 1.51 2004/11/03 16:24:57 mkdist Exp $
Summary: BProc: Beowulf Distributed Process Space
Name: bproc
Version: 4.0.0pre8
Release: 1
License: GPL
Group: System Environment/Daemons
Source: bproc-%{version}.tar.gz
Buildroot: /var/tmp/bproc

Packager: Erik Hendriks <erik@hendriks.cx>

# 32bit/64bit compatibility stuff.
# I don't think anybody's macros define something like this....
%define ARCH %(echo %{_target_cpu} | sed -e s/i.86/i386/)
%ifarch x86_64 ppc64
%define compat32 1
%define _lib32    lib
%define _lib32dir %{_exec_prefix}/%{_lib32}
%endif

Requires: bproc-libs

# RPM magic weird stuff
#define _unpackaged_files_terminate_build 0
%define debug_package %{nil}

%description
The BProc distributed process space is a central process
distribution and control technology intended for use in high
performance compute clusters.

This package contains the daemons and utility programs.

#--------------------------------------------------------------------------
%package libs
Summary: Beowulf Distributed Process Space Runtime Libraries
Group: System Environment/Libraries

%description libs
The BProc distributed process space is a central process
distribution and control technology intended for use in high
performance compute clusters.

This package contains the dynamic libraries required to run BProc
applications.  Note that these libraries can be used as stubs when the
rest of the BProc system is not present.

#--------------------------------------------------------------------------
%package devel
Summary: Beowulf Distributed Process Space Development Files
Group: System Environment/Libraries
Requires: bproc-libs

%description devel
The BProc distributed process space is a central process
distribution and control technology intended for use in high
performance compute clusters.

This package contains the development libraries required to write
applications which use the BProc system directly.

#--------------------------------------------------------------------------
%prep
%setup -q

#--------------------------------------------------------------------------
%build
# We don't build modules here, hence the "LINUX=" bit.
make LINUX= ARCH=%{ARCH} \
	libdir=%{_libdir} includedir=%{_includedir} mandir=%{_mandir} \
	sysconfdir=%{_sysconfdir} bindir=%{_bindir} sbindir=%{_sbindir}

%install
rm -rf   $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/clustermatic
mkdir -p $RPM_BUILD_ROOT/%{_bindir}
mkdir -p $RPM_BUILD_ROOT/%{_sbindir}
mkdir -p $RPM_BUILD_ROOT/%{_libdir}
mkdir -p $RPM_BUILD_ROOT/%{_includedir}/sys
mkdir -p $RPM_BUILD_ROOT/%{_mandir}/man{1,2,3,5,8}
mkdir -p $RPM_BUILD_ROOT/%{_localstatedir}/log/clustermatic
mkdir -p $RPM_BUILD_ROOT/bpfs

make LINUX= ARCH=%{ARCH} prefix=$RPM_BUILD_ROOT \
	libdir=%{_libdir} includedir=%{_includedir} mandir=%{_mandir} \
	sysconfdir=%{_sysconfdir} bindir=%{_bindir} sbindir=%{_sbindir} \
	install

# one little patch...
ln -sf bplib $RPM_BUILD_ROOT/%{_sbindir}/vmadlib

#---------------------------------------------------------------------
%clean
rm -rf $RPM_BUILD_ROOT

%post libs
if [ -x /sbin/ldconfig ] ; then /sbin/ldconfig ; fi

%files
%defattr(-,root,root)
%dir %{_sysconfdir}/clustermatic
%config(noreplace) %{_sysconfdir}/clustermatic/config
%{_sbindir}/bpmaster
%{_sbindir}/bpslave
%{_libdir}/libbpslave.a
%{_sbindir}/bpctl
%{_sbindir}/vmadlib
%{_sbindir}/bplib
%{_bindir}/bpsh
%{_bindir}/bpcp
%{_bindir}/bpstat
%dir %{_localstatedir}/log/clustermatic
%{_mandir}/man1/*
%{_mandir}/man5/*
%{_mandir}/man8/*
%dir /bpfs

%files libs
%defattr(-,root,root)
%{_libdir}/libbproc.so.*

%files devel
%defattr(-,root,root)
%{_includedir}/sys/*
%{_libdir}/libbproc.a
%{_libdir}/libbproc.so
%{_mandir}/man2/*
%{_mandir}/man3/*

%if %{compat32}
%package libs-32bit
Summary: Beowulf Distributed Process Space Runtime Libraries
Group: System Environment/Libraries

%files libs-32bit
%defattr(-,root,root)
%{_lib32dir}/libbproc.so.*

%description libs-32bit
The BProc distributed process space is a central process
distribution and control technology intended for use in high
performance compute clusters.

This package contains the dynamic libraries required to run BProc
applications.  Note that these libraries can be used as stubs when the
rest of the BProc system is not present.

%package devel-32bit
Summary: Beowulf Distributed Process Space Development Files
Group: System Environment/Libraries
Requires: bproc-libs-32bit

%description devel-32bit
The BProc distributed process space is a central process
distribution and control technology intended for use in high
performance compute clusters.

This package contains the development libraries required to write
applications which use the BProc system directly.

%files devel-32bit
%defattr(-,root,root)
%{_lib32dir}/libbproc.a
%{_lib32dir}/libbproc.so
%endif


%changelog
* Tue Nov  3 2004 Erik Hendriks <erik@hendriks.cx>
- Added stuff to built '-32bit' packagages on 64 bit architectures
  with compatibility modes.

* Tue Nov  2 2004 Erik Hendriks <erik@hendriks.cx>
- Ripped out all kernel module building stuff.

* Wed Oct 22 2003 Erik Hendriks <erik@hendriks.cx>
- Significant cleanup to allow RPM to tell us where things SHOULD be
  installed.  This was motivated by opteron and the /usr/lib64 thing.

* Tue Aug 13 2002 Erik Hendriks <erik@hendriks.cx>
- Fixed depmod some more and added more include files.

* Sat Mar 16 2002 Erik Hendriks <erik@hendriks.cx>
- Fixed depmod commands in post-install scripts

* Thu Jan  2 2002 Erik Hendriks <erik@hendriks.cx>
- Split the modules RPM into SMP and non-SMP.

* Fri Oct 16 2001 Erik Hendriks <erik@hendriks.cx>
- Added some kernel version information to the bproc-modules release tag.
- Moved some docs around
- Updated for Red Hat 7.x type build environment

* Wed Oct  3 2001 Erik Hendriks <erik@hendriks.cx>
- Updated for new docs and file names

* Sun Jun 10 2001 Erik Hendriks <erik@hendriks.cx>
- Updated build section to work with normal kernel trees as well as
  Red Hat (6.x) style kernel trees.

* Fri Jul 14 2000 Erik Hendriks <erik@hendriks.cx>
- Split some of pieces off into separate RPMs

* Mon Jul 10 2000 Erik Hendriks <erik@hendriks.cx>
- More tweaking
- Removed -modules RPM
- Added better handling of config files.

* Mon Jun 12 2000 Erik Hendriks <erik@hendriks.cx>
- Initial version
