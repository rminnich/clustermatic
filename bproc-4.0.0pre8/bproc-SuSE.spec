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
# $Id: bproc-SuSE.spec,v 1.1 2004/10/01 19:44:48 mkdist Exp $
Summary: BProc: Beowulf Distributed Process Space
Name: bproc
Version: 4.0.0pre8
Release: 1
License: GPL
Group: System Environment/Daemons
Source: bproc-%{version}.tar.gz
Buildroot: /var/tmp/bproc

Packager: Erik Hendriks <erik@hendriks.cx>

Requires: bproc-libs

# RPM magic weird stuff
#%define _unpackaged_files_terminate_build 0
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
# kernel chunks for SuSE
%package -n km_bproc
Summary: Kernel Module Sub-Package for bproc
Group: System Environment/Daemons

%description -n km_bproc
The BProc distributed process space is a central process
distribution and control technology intended for use in high
performance compute clusters.

This package contains the source for the kernel modules.  It is
required to build the kernel modules during kernel build.

#--------------------------------------------------------------------------
%prep
%setup -q

#--------------------------------------------------------------------------
%build
# This is a terrible terrible hack.  We will unfortunately need
# autoconf or something autoconf-like in the near future.
%ifarch alpha ppc
%define have_xattr n
%else
%define have_xattr y
%endif

# For SuSE's scheme, we build everything *except* the kernel modules.
# Hence the LINUX= part.

make LINUX= HAVE_XATTR=%{have_xattr} \
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

make LINUX= HAVE_XATTR=%{have_xattr} prefix=$RPM_BUILD_ROOT \
	libdir=%{_libdir} includedir=%{_includedir} mandir=%{_mandir} \
	sysconfdir=%{_sysconfdir} bindir=%{_bindir} sbindir=%{_sbindir} \
	install

# one little patch...
ln -sf bplib $RPM_BUILD_ROOT/%{_sbindir}/vmadlib


#--- km_bproc: kernel module stuff
DEST=$RPM_BUILD_ROOT/usr/src/kernel-modules/bproc
mkdir -p $DEST
mkdir -p $DEST/kernel
mkdir -p $DEST/vmadump
mkdir -p $DEST/clients/sys

cp -a Makefile.conf $DEST
cp -a kernel/* $DEST/kernel
cp -a clients/sys/bproc_common.h $DEST/clients/sys
cp -a vmadump/vmadump*.{c,h} $DEST/vmadump

# Stub makefile that will work with the kernel build system.
cat <<EOF > $DEST/Makefile
.PHONY: modules install
modules:
	\$(MAKE) -C kernel LINUX=\$(KERNEL_SOURCE)
install:
	\$(MAKE) -C kernel LINUX=\$(KERNEL_SOURCE) install
EOF

#---------------------------------------------------------------------
%clean
rm -rf $RPM_BUILD_ROOT

%post libs
if [ -x /sbin/ldconfig ] ; then /sbin/ldconfig ; fi

%files
%defattr(-,root,root)
# These docs are old....
#%doc doc/userguide.sgml doc/internals.sgml
# The RPM does not contain a config file... This
# will be provided by the beoboot RPM...
#%config(noreplace) %{_sysconfdir}/clustermatic/config
%dir %{_sysconfdir}/clustermatic
%config(noreplace) %{_sysconfdir}/clustermatic/config
%{_sbindir}/bpmaster
%{_sbindir}/bpslave
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
%{_libdir}/libbpslave.a
%{_mandir}/man2/*
%{_mandir}/man3/*


%files -n km_bproc
%dir %attr (-,root,root) /usr/src/kernel-modules
%dir %attr (-,root,root) /usr/src/kernel-modules/bproc
%attr (-,root,root) /usr/src/kernel-modules/bproc/*




%changelog
* Fri Oct 01 2004 Erik Hendriks <erik@hendriks.cx>
- Modifed for SuSE's kernel package scheme.  This is MUCH simpler now.

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
