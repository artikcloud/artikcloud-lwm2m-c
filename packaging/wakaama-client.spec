Name: wakaama-client
Version: 1.3
Release: 0%{?dist}
License: EDL&EPL
Summary: Implementation of the Open Mobile Alliance's LightWeight M2M protocol (LWM2M)
Group: Development/Libraries
URL: https://github.com/obgm/wakaama

Provides: lib%{name}.so.1

%description
Implementation of the Open Mobile Alliance's LightWeight M2M protocol

%package devel
Summary: Development files for implementation of the Open Mobile Alliance's LightWeight M2M protocol (LWM2M)
Group: Development/Libraries
License: EDL&EPL

Requires: %{name} = %{version}-%{release}

%description devel
Implementation of the Open Mobile Alliance's LightWeight M2M protocol (devel)

%package examples
Summary: Example programs that use wakaama-client library
Group: Development/Libraries

Requires: %{name} = %{version}-%{release}

%description examples
This package contains akc_client and akc_ota

%prep
rm -rf %{_builddir}/*
rm -rf %{buildroot}/*
cd %{_builddir}

%build
echo %{_host_cpu}
%if %(echo %arm | egrep -c %{_host_cpu})
cmake %{_srcdir} -DCMAKE_INSTALL_PREFIX=%{_prefix} \
                 -DCMAKE_BUILD_TYPE=%{?debug:Debug}%{?!debug:Release} \
                 -DLWM2M_USE_EMBEDDED_OPENSSL=0
%else
cmake %{_srcdir} -DCMAKE_TOOLCHAIN_FILE=%{_srcdir}/target/toolchain-cross-arm.cmake \
                 -DCMAKE_INSTALL_PREFIX=%{_prefix} \
                 -DCMAKE_SYSROOT=%{_sysrootdir} \
                 -DCMAKE_BUILD_TYPE=%{?debug:Debug}%{?!debug:Release} \
                 -DLWM2M_USE_EMBEDDED_OPENSSL=0
%endif
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
cp %{_srcdir}/EDL-v1.0 %{_builddir}
cp %{_srcdir}/EPL-v1.0 %{_builddir}
cp %{_srcdir}/README.md %{_builddir}
cp %{_srcdir}/README-wakaama.md %{_builddir}

%files
%defattr(-,root,root,-)
%doc EDL-v1.0 EPL-v1.0 README.md README-wakaama.md
%{_libdir}/*.so.*

%files devel
%defattr(-,root,root,-)
%{_libdir}/*.so
%{_includedir}/*

%files examples
%defattr(-,root,root,-)
%{_bindir}/akc_client
%{_bindir}/akc_ota
