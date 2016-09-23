Name: wakaama-client
Version: 1.0
Release: 1%{?dist}
License: EDL&EPL
Summary: Implementation of the Open Mobile Alliance's LightWeight M2M protocol (LWM2M)
Group: Development/Libraries
URL: https://github.com/obgm/wakaama

BuildRequires: cmake
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

%prep
rm -rf %{_builddir}/*
rm -rf %{buildroot}/*
cd %{_builddir}

%build
cmake %{_srcdir} -DCMAKE_INSTALL_PREFIX=%{_prefix}
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
%make_install
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

