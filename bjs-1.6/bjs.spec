# $Id: bjs.spec,v 1.7 2004/11/03 17:49:02 mkdist Exp $
Summary: BJS - BProc Job Scheduler
Name: bjs
Version: 1.6
Release: 1
Source0: %{name}-%{version}.tar.gz
License: GPL
Group: System/Daemons
BuildRoot: %{_tmppath}/%{name}-root
BuildRequires: bproc-devel

%define debug_package %{nil}

%description
BJS (BProc Job Scheduler) is a simple job scheduler designed for use
in clusters running BProc.

%prep
%setup -q

%build
make libdir=%{_libdir} includedir=%{_includedir} mandir=%{_mandir} \
     sysconfdir=%{_sysconfdir} bindir=%{_bindir} sbindir=%{_sbindir}


%install
rm -rf $RPM_BUILD_ROOT
make prefix=$RPM_BUILD_ROOT \
     libdir=%{_libdir} includedir=%{_includedir} mandir=%{_mandir} \
     sysconfdir=%{_sysconfdir} bindir=%{_bindir} sbindir=%{_sbindir} \
     install

%clean
rm -rf $RPM_BUILD_ROOT

%post
if [ -x /sbin/chkconfig ] ; then
    /sbin/chkconfig --add bjs
fi

%preun
if [ "$1" = "0" ]; then
    if [ -x /sbin/chkconfig ] ; then
	/sbin/chkconfig --del bjs
    fi
fi

%files
%defattr(-,root,root)
%config(noreplace) %{_sysconfdir}/clustermatic/bjs.conf
%{_sysconfdir}/init.d/bjs
%{_bindir}/*
%{_sbindir}/*
%{_libdir}/bjs
%dir %{_localstatedir}/spool/bjs

%changelog
* Mon Oct 28 2002  <hendriks@lanl.gov>
- Initial build.


