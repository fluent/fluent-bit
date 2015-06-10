Name: monkey
Version: 1.4.0
Release: 1%{?dist}
Summary: A fast and lightweight web server for Linux
Group: System Environment/Daemons
License: GPLv2+
URL: http://www.monkey-project.com
Source: http://www.monkey-project.com/releases/1.4/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

#BuildRequires: gettext
#Requires(pre): shadow-utils


%description
Monkey is a fast and lightweight web server for Linux. It has been
designed to be very scalable with low memory and CPU consumption, the
perfect solution for embedded and high production environments.


%prep
%setup -q


%build
./configure \
	--prefix=%{_prefix} \
	--bindir=%{_bindir} \
	--incdir=%{_prefix}/include/monkey/ \
	--sysconfdir=%{_sysconfdir}/%{name} \
	--datadir=%{_var}/www/%{name} \
	--logdir=%{_var}/log/%{name} \
	--plugdir=%{_libexecdir}/%{name}


make %{?_smp_mflags}


%install
rm -rf %{buildroot}
install -d %{buildroot}%{_var}/log/%{name}

make install DESTDIR=%{buildroot}

%{__sed} -i 's/User nobody/User www-data/g' \
	 %{buildroot}/etc/%{name}/monkey.conf

%clean
rm -rf %{buildroot}


%pre
getent group monkey  > /dev/null || groupadd -r monkey
getent passwd monkey > /dev/null || \
  useradd -r -g monkey -d %{_var}/www/%{name}  -s /sbin/nologin \
	  -c "Monkey HTTP Daemon" monkey
exit 0


%files
%defattr(-,root,root)
%doc README LICENSE ChangeLog*
%attr(644,root,root) %config(noreplace) %{_sysconfdir}/%{name}/monkey.conf
%attr(644,root,root) %config(noreplace) %{_sysconfdir}/%{name}/monkey.mime
%attr(644,root,root) %{_sysconfdir}/%{name}/plugins
%attr(644,root,root) %{_sysconfdir}/%{name}/plugins.load
%attr(644,root,root) %{_sysconfdir}/%{name}/sites
%attr(700,root,root) %{_bindir}
%attr(644,root,root) %{_libexecdir}
%attr(700,monkey,monkey) %{_var}/www/%{name}
%attr(0750, monkey, monkey) %{_var}/log/%{name}

# Header files
%attr(644,root,root) %{_prefix}/include/monkey/MKPlugin.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_cache.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_clock.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_config.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_connection.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_env.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_epoll.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_file.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_header.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_http.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_http_status.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_info.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_iov.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_lib.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_limits.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_linuxtrace.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_list.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_macros.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_memory.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_method.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_mimetype.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_plugin.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_rbtree.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_rbtree_augmented.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_request.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_scheduler.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_server.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_signals.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_socket.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_string.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_user.h
%attr(644,root,root) %{_prefix}/include/monkey/mk_utils.h
%attr(644,root,root) %{_prefix}/include/monkey/monkey.h

# Manpages
%attr(644,root,root) /usr/man/man1/banana.1.gz
%attr(644,root,root) /usr/man/man1/monkey.1.gz
%attr(644,root,root) /usr/man/man3/mklib_callback_set.3.gz
%attr(644,root,root) /usr/man/man3/mklib_config.3.gz
%attr(644,root,root) /usr/man/man3/mklib_init.3.gz
%attr(644,root,root) /usr/man/man3/mklib_mimetype_add.3.gz
%attr(644,root,root) /usr/man/man3/mklib_mimetype_list.3.gz
%attr(644,root,root) /usr/man/man3/mklib_scheduler_worker_info.3.gz
%attr(644,root,root) /usr/man/man3/mklib_start.3.gz
%attr(644,root,root) /usr/man/man3/mklib_stop.3.gz
%attr(644,root,root) /usr/man/man3/mklib_vhost_config.3.gz
%attr(644,root,root) /usr/man/man3/mklib_vhost_list.3.gz
%attr(644,root,root) /usr/man/man3/monkey-api.3.gz

# Libraries
%attr(744,root,root) /usr/lib/libmonkey.so
%attr(744,root,root) /usr/lib/pkgconfig/monkey.pc

%postun
cat   %{_var}/log/%{name}/monkey.pid  | xargs kill -9 > /dev/null 2>&1
rm    %{_var}/log/%{name}/*pid > /dev/null 2>&1
rmdir %{_var}/log/%{name} > /dev/null 2>&1
rmdir %{_sysconfdir}/%{name} > /dev/null 2>&1


%changelog
* Sun Dec 22 2013 Eduardo Silva <edsiper@gmail.com> - 1.4.0-1
- Testing new spec file for v1.4

* Tue Aug 24 2010  Antonio Salles <antonio@salles.cl> - 0.11.1-2
- Spec rebuild. Now it work fine with Fedora.

* Thu Jul 22 2010  Horst H. von Brand <vonbrand@inf.utfsm.cl> - 0.11.0-2
- First cut at cleaning up specfile according to Fedora guidelines

* Thu Jul 08 2010  Eduardo Silva <edsiper at gmail.com> 0.11.0-1
- Initial rpm package for Fedora 13
