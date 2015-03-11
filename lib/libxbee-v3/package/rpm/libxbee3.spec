Name: libxbee
Summary: A C/C++ library to aid the use of Digi XBee radios in API mode
%define version 3.0.11
Release: 1
Source: libxbee-v%{version}.tgz

License: LGPLv3
#BuildRequires: make, gcc, binutils, coreutils, gzip, man2html
Group: System/Libraries
Version: %{version}
BuildRoot: /ver/tmp/${name}-buildroot


%description
A C/C++ library to aid the use of Digi XBee radios in API mode

%prep
%setup -q

%build
make configure
make -j $(echo $(cat /proc/cpuinfo | grep '^processor' | wc -l)*2 | bc)

%install
rm -rf ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}/usr/include
mkdir -p ${RPM_BUILD_ROOT}/usr/lib
mkdir -p ${RPM_BUILD_ROOT}/usr/share/man/man3
sudo SYS_ROOT=${RPM_BUILD_ROOT} make install

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(-,root,root)
/usr/lib/libxbee.a
/usr/lib/libxbee.a.%{version}
/usr/lib/libxbee.so
/usr/lib/libxbee.so.%{version}
/usr/lib/libxbee.so.%{version}.dbg
/usr/lib/libxbeep.a
/usr/lib/libxbeep.a.%{version}
/usr/lib/libxbeep.so
/usr/lib/libxbeep.so.%{version}
/usr/lib/libxbeep.so.%{version}.dbg
/usr/include/xbee.h
/usr/include/xbeep.h
/usr/share/man/man3/libxbee.3.gz

/usr/share/man/man3/libxbee_buildtime.3.gz
/usr/share/man/man3/libxbee_commit.3.gz
/usr/share/man/man3/libxbee_committer.3.gz
/usr/share/man/man3/libxbee_revision.3.gz

/usr/share/man/man3/xbee_conCallbackSet.3.gz
/usr/share/man/man3/xbee_conDataSet.3.gz
/usr/share/man/man3/xbee_conEnd.3.gz
/usr/share/man/man3/xbee_conInfo.3.gz
/usr/share/man/man3/xbee_conRxWait.3.gz
/usr/share/man/man3/xbee_conSleepSet.3.gz
/usr/share/man/man3/xbee_conSleepStates.3.gz
/usr/share/man/man3/xbee_conValidate.3.gz
/usr/share/man/man3/xbee_connTx.3.gz
/usr/share/man/man3/xbee_convTx.3.gz
/usr/share/man/man3/xbee_err.3.gz
/usr/share/man/man3/xbee_errors.3.gz
/usr/share/man/man3/xbee_logLevelSet.3.gz
/usr/share/man/man3/xbee_logTargetGet.3.gz
/usr/share/man/man3/xbee_logTargetSet.3.gz
/usr/share/man/man3/xbee_modeGet.3.gz
/usr/share/man/man3/xbee_netStop.3.gz
/usr/share/man/man3/xbee_netvStart.3.gz
/usr/share/man/man3/xbee_pktAnalogGet.3.gz
/usr/share/man/man3/xbee_pktDigitalGet.3.gz
/usr/share/man/man3/xbee_pktFree.3.gz
/usr/share/man/man3/xbee_shutdown.3.gz
/usr/share/man/man3/xbee_validate.3.gz
/usr/share/man/man3/xbee_vsetup.3.gz
/usr/share/man/man3/xbee_pktDataGet.3.gz
/usr/share/man/man3/xbee_conSleepGet.3.gz
/usr/share/man/man3/xbee_conInfoGet.3.gz
/usr/share/man/man3/xbee_logLevelGet.3.gz
/usr/share/man/man3/xbee_conPurge.3.gz
/usr/share/man/man3/xbee_conCallbackGet.3.gz
/usr/share/man/man3/xbee_log.3.gz
/usr/share/man/man3/xbee_conNew.3.gz
/usr/share/man/man3/xbee_pkt.3.gz
/usr/share/man/man3/xbee_errorToStr.3.gz
/usr/share/man/man3/xbee_modeGetList.3.gz
/usr/share/man/man3/xbee_netStart.3.gz
/usr/share/man/man3/xbee_attachEOFCallback.3.gz
/usr/share/man/man3/xbee_conRx.3.gz
/usr/share/man/man3/xbee_conDataGet.3.gz
/usr/share/man/man3/xbee_pktValidate.3.gz
/usr/share/man/man3/xbee_setup.3.gz
/usr/share/man/man3/xbee_conSettings.3.gz
/usr/share/man/man3/xbee_conGetTypes.3.gz
/usr/share/man/man3/xbee_conTx.3.gz
/usr/share/man/man3/xbee_conAddress.3.gz
/usr/share/man/man3/xbee_conGetXBee.3.gz
/usr/share/man/man3/xbee_conTypeGet.3.gz
/usr/share/man/man3/xbee_connxTx.3.gz
/usr/share/man/man3/xbee_convxTx.3.gz
/usr/share/man/man3/xbee_conxTx.3.gz
/usr/share/man/man3/xbee_dataGet.3.gz
/usr/share/man/man3/xbee_dataSet.3.gz

%changelog
* Wed May 30 2012 Attie Grande <attie@attie.co.uk>
- created RPM build infrastructure
