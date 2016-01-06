%bcond_with kdbus
%define release_flags %{?with_kdbus:+kdbus}

# "enable foo" will turn into --enable-foo or --disable-foo
# depending "with_foo" macro
%define enable() %{expand:%%{?with_%{1}:--enable-%{1}}%%{!?with_%{1}:--disable-%{1}}}

%define release_flags %{?with_kdbus:+kdbus}

%define WITH_RANDOMSEED 0

Name:           systemd
Version:        219
Release:        0%{?release_flags}
# For a breakdown of the licensing, see README
License:        LGPL-2.0+ and MIT and GPL-2.0+
Summary:        A System and Service Manager
Url:            http://www.freedesktop.org/wiki/Software/systemd
Group:          Base/Startup
Source0:        http://www.freedesktop.org/software/systemd/%{name}-%{version}.tar.xz
Source1:        pamconsole-tmp.conf
Source2:        %{name}-rpmlintrc
Source3:        default.target.ivi
Source1001:     systemd.manifest
BuildRequires:  gperf
BuildRequires:  intltool >= 0.40.0
BuildRequires:  libacl-devel
BuildRequires:  libblkid-devel >= 2.20
BuildRequires:  libcap-devel
BuildRequires:  libgcrypt-devel
BuildRequires:  libkmod-devel >= 14
BuildRequires:  xsltproc
BuildRequires:  docbook-xsl-stylesheets
BuildRequires:  pam-devel
BuildRequires:  pkgconfig
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(liblzma)
BuildRequires:  pkgconfig(libkmod)
BuildRequires:  pkgconfig(mount)
Requires:       dbus
Requires:       filesystem
Requires(post): coreutils
Requires(post): gawk
Requires(pre):  coreutils
Requires(pre):  /usr/bin/getent
Requires(pre):  /usr/sbin/groupadd

Obsoletes:      SysVinit < 2.86-24
Obsoletes:      sysvinit < 2.86-24
Provides:       SysVinit = 2.86-24
Provides:       sysvinit = 2.86-24
Provides:       /bin/systemctl
Provides:       /sbin/shutdown
Provides:       udev = %{version}
Obsoletes:      udev < 183

%description
systemd is a system and service manager for Linux, compatible with
SysV and LSB init scripts. systemd provides aggressive parallelization
capabilities, uses socket and D-Bus activation for starting services,
offers on-demand starting of daemons, keeps track of processes using
Linux cgroups, supports snapshotting and restoring of the system
state, maintains mount and automount points and implements an
elaborate transactional dependency-based service control logic. It can
work as a drop-in replacement for sysvinit.

%package -n libsystemd
License:        LGPL-2.0+ and MIT
Summary:        Systemd libraries
Group:          Base/Startup
Obsoletes:      libudev < 183
Obsoletes:      systemd < 185-4
Conflicts:      systemd < 185-4

%description -n libsystemd
Libraries for systemd and udev, as well as the systemd PAM module.

%package devel
License:        LGPL-2.0+ and MIT
Summary:        Development headers for systemd
Requires:       %{name} = %{version}
Requires:		libsystemd = %{version}
Provides:       libudev-devel = %{version}
Obsoletes:      libudev-devel < 183

%description devel
Development headers and auxiliary files for developing applications for systemd.

%package analyze
License:        LGPL-2.0+
Summary:        Tool for processing systemd profiling information
Requires:       %{name} = %{version}
Obsoletes:      systemd < 38-5

%description analyze
'systemd-analyze blame' lists which systemd unit needed how much time to finish
initialization at boot.
'systemd-analyze plot' renders an SVG visualizing the parallel start of units
at boot.

%package -n libgudev
License:        LGPL-2.0+
Summary:        Libraries for adding libudev support to applications that use glib
Requires:       %{name} = %{version}

%description -n libgudev
This package contains the libraries that make it easier to use libudev
functionality from applications that use glib.

%package -n libgudev-devel
License:        LGPL-2.0+
Summary:        Header files for adding libudev support to applications that use glib
Requires:       libgudev = %{version}

%description -n libgudev-devel
This package contains the header and pkg-config files for developing
glib-based applications using libudev functionality.

%prep
%setup -q
cp %{SOURCE1001} .

%build
%autogen
%configure \
        %{enable kdbus} \
%if ! %{WITH_RANDOMSEED}
        --disable-randomseed \
%endif
        --enable-compat-libs \
        --enable-bootchart \
        --disable-hwdb \
        --disable-sysusers \
        --disable-firstboot \
        --disable-timesyncd \
        --disable-resolved \
        --disable-networkd \
        --libexecdir=%{_prefix}/lib \
        --docdir=%{_docdir}/systemd \
        --disable-static \
        --with-sysvinit-path= \
        --with-sysvrcnd-path= \
        --with-smack-run-label=System \
        cc_cv_CFLAGS__flto=no
make %{?_smp_mflags} \
        systemunitdir=%{_unitdir} \
        userunitdir=%{_unitdir_user}

%install
%make_install
%find_lang %{name}
cat <<EOF >> systemd.lang
%lang(fr) /usr/lib/systemd/catalog/systemd.fr.catalog
%lang(it) /usr/lib/systemd/catalog/systemd.it.catalog
%lang(ru) /usr/lib/systemd/catalog/systemd.ru.catalog
%lang(pl) /usr/lib/systemd/catalog/systemd.pl.catalog
%lang(pt_BR) /usr/lib/systemd/catalog/systemd.pt_BR.catalog
EOF

# udev links
/usr/bin/mkdir -p %{buildroot}/%{_sbindir}
/usr/bin/ln -sf ../bin/udevadm %{buildroot}%{_sbindir}/udevadm
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/firmware/updates

# Create SysV compatibility symlinks. systemctl/systemd are smart
# enough to detect in which way they are called.
/usr/bin/ln -s ../lib/systemd/systemd %{buildroot}%{_sbindir}/init
/usr/bin/ln -s ../lib/systemd/systemd %{buildroot}%{_bindir}/systemd
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/reboot
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/halt
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/poweroff
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/shutdown
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/telinit
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/runlevel

# legacy links
/usr/bin/ln -s loginctl %{buildroot}%{_bindir}/systemd-loginctl

# We create all wants links manually at installation time to make sure
# they are not owned and hence overriden by rpm after the used deleted
# them.
/usr/bin/rm -r %{buildroot}%{_sysconfdir}/systemd/system/*.target.wants

# Make sure the ghost-ing below works
/usr/bin/touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel2.target
/usr/bin/touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel3.target
/usr/bin/touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel4.target
/usr/bin/touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel5.target

# Make sure these directories are properly owned
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/basic.target.wants
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/default.target.wants
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/dbus.target.wants
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/syslog.target.wants

# Make sure the user generators dir exists too
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-generators
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/user-generators

# Create new-style configuration files so that we can ghost-own them
/usr/bin/touch %{buildroot}%{_sysconfdir}/hostname
/usr/bin/touch %{buildroot}%{_sysconfdir}/vconsole.conf
/usr/bin/touch %{buildroot}%{_sysconfdir}/locale.conf
/usr/bin/touch %{buildroot}%{_sysconfdir}/machine-id
/usr/bin/touch %{buildroot}%{_sysconfdir}/machine-info
/usr/bin/touch %{buildroot}%{_sysconfdir}/timezone

/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-preset/
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/user-preset/

# Make sure the shutdown/sleep drop-in dirs exist
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-shutdown/
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-sleep/

# Make sure the NTP units dir exists
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/ntp-units.d/

# Install modprobe fragment
/usr/bin/mkdir -p %{buildroot}%{_sysconfdir}/modprobe.d/

# Fix the dangling /var/lock -> /run/lock symlink
install -Dm644 tmpfiles.d/legacy.conf %{buildroot}%{_prefix}/lib/tmpfiles.d/legacy.conf

install -m644 %{SOURCE1} %{buildroot}%{_prefix}/lib/tmpfiles.d/

install -m 755 -d %{buildroot}/%{_prefix}/lib/systemd/system
%if "%{profile}" == "ivi"
rm -f %{buildroot}/%{_prefix}/lib/systemd/system/default.target
install -m 644 %{SOURCE3} %{buildroot}/%{_prefix}/lib/systemd/system/default.target
%endif

rm -rf %{buildroot}/%{_docdir}/%{name}

# Disable some useless services in Tizen
rm -rf %{buildroot}/%{_prefix}/lib/systemd/system/sysinit.target.wants/dev-hugepages.mount
rm -rf %{buildroot}/%{_prefix}/lib/systemd/system/sysinit.target.wants/sys-fs-fuse-connections.mount
rm -rf %{buildroot}/%{_prefix}/lib/systemd/system/sysinit.target.wants/systemd-binfmt.service
rm -rf %{buildroot}/%{_prefix}/lib/systemd/system/sysinit.target.wants/systemd-modules-load.service
rm -rf %{buildroot}/%{_prefix}/lib/systemd/system/sysinit.target.wants/systemd-ask-password-console.path
rm -rf %{buildroot}/%{_prefix}/lib/systemd/system/multi-user.target.wants/systemd-ask-password-wall.path

# Move macros to the proper location for Tizen
mkdir -p %{buildroot}%{_sysconfdir}/rpm
install -m644 src/core/macros.systemd %{buildroot}%{_sysconfdir}/rpm/macros.systemd
rm -f %{buildroot}%{_prefix}/lib/rpm/macros.d/macros.systemd

# Exclude ELF binaries
rm -f %{buildroot}/%{_prefix}/lib/systemd/system-generators/systemd-debug-generator
rm -f %{buildroot}/%{_prefix}/lib/systemd/system-generators/systemd-hibernate-resume-generator

# end of install
%pre
/usr/bin/getent group cdrom >/dev/null 2>&1 || /usr/sbin/groupadd -r -g 11 cdrom >/dev/null 2>&1 || :
/usr/bin/getent group tape >/dev/null 2>&1 || /usr/sbin/groupadd -r -g 33 tape >/dev/null 2>&1 || :
/usr/bin/getent group dialout >/dev/null 2>&1 || /usr/sbin/groupadd -r -g 18 dialout >/dev/null 2>&1 || :
/usr/bin/getent group floppy >/dev/null 2>&1 || /usr/sbin/groupadd -r -g 19 floppy >/dev/null 2>&1 || :
/usr/bin/systemctl stop systemd-udevd-control.socket systemd-udevd-kernel.socket systemd-udevd.service >/dev/null 2>&1 || :

# Rename configuration files that changed their names
/usr/bin/mv -n %{_sysconfdir}/systemd/systemd-logind.conf %{_sysconfdir}/systemd/logind.conf >/dev/null 2>&1 || :
/usr/bin/mv -n %{_sysconfdir}/systemd/systemd-journald.conf %{_sysconfdir}/systemd/journald.conf >/dev/null 2>&1 || :

%post
/usr/bin/systemd-machine-id-setup > /dev/null 2>&1 || :
%if %{WITH_RANDOMSEED}
/usr/lib/systemd/systemd-random-seed save > /dev/null 2>&1 || :
%endif
/usr/bin/systemctl daemon-reexec > /dev/null 2>&1 || :
/usr/bin/systemctl start systemd-udevd.service >/dev/null 2>&1 || :

%postun
if [ $1 -ge 1 ] ; then
        /usr/bin/systemctl daemon-reload > /dev/null 2>&1 || :
        /usr/bin/systemctl try-restart systemd-logind.service >/dev/null 2>&1 || :
fi

%preun
if [ $1 -eq 0 ] ; then
        /usr/bin/systemctl disable \
                getty@.service \
                remote-fs.target \
                systemd-readahead-replay.service \
                systemd-readahead-collect.service >/dev/null 2>&1 || :
fi

%post -n libsystemd -p /sbin/ldconfig
%postun -n libsystemd  -p /sbin/ldconfig

%post -n libgudev -p /sbin/ldconfig
%postun -n libgudev -p /sbin/ldconfig


%lang_package

%files
%manifest %{name}.manifest
%config %{_sysconfdir}/pam.d/systemd-user
%{_bindir}/bootctl
%{_bindir}/busctl
%{_bindir}/kernel-install
%{_bindir}/machinectl
%{_bindir}/systemd-run
%dir %{_prefix}/lib/kernel
%dir %{_prefix}/lib/kernel/install.d
%{_prefix}/lib/kernel/install.d/50-depmod.install
%{_prefix}/lib/kernel/install.d/90-loaderentry.install
%{_bindir}/hostnamectl
%{_bindir}/localectl
%{_bindir}/coredumpctl
%{_bindir}/timedatectl
%dir %{_sysconfdir}/systemd
%dir %{_sysconfdir}/systemd/system
%dir %{_sysconfdir}/systemd/user
%dir %{_sysconfdir}/tmpfiles.d
%dir %{_sysconfdir}/sysctl.d
%dir %{_sysconfdir}/modules-load.d
%dir %{_sysconfdir}/binfmt.d
%{_datadir}/bash-completion/*
%dir %{_datadir}/zsh/site-functions
%{_datadir}/zsh/site-functions/*
%dir %{_sysconfdir}/udev
%dir %{_sysconfdir}/udev/rules.d
%dir %{_prefix}/lib/systemd
%dir %{_prefix}/lib/systemd/system
%dir %{_prefix}/lib/systemd/system-generators
%dir %{_prefix}/lib/systemd/user-generators
%dir %{_prefix}/lib/systemd/system-preset
%dir %{_prefix}/lib/systemd/user-preset
%dir %{_prefix}/lib/systemd/system-shutdown
%dir %{_prefix}/lib/systemd/system-sleep
%dir %{_prefix}/lib/tmpfiles.d
%dir %{_prefix}/lib/sysctl.d
%dir %{_prefix}/lib/modules-load.d
%dir %{_prefix}/lib/binfmt.d
%dir %{_prefix}/lib/firmware
%dir %{_prefix}/lib/firmware/updates
%dir %{_datadir}/systemd
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.systemd1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.hostname1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.login1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.locale1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.timedate1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.machine1.conf
%config(noreplace) %{_sysconfdir}/systemd/bootchart.conf
%config(noreplace) %{_sysconfdir}/systemd/coredump.conf
%config(noreplace) %{_sysconfdir}/systemd/system.conf
%config(noreplace) %{_sysconfdir}/systemd/user.conf
%config(noreplace) %{_sysconfdir}/systemd/logind.conf
%config(noreplace) %{_sysconfdir}/systemd/journald.conf
%config(noreplace) %{_sysconfdir}/udev/udev.conf
%{_sysconfdir}/xdg/systemd
%ghost %config(noreplace) %{_sysconfdir}/hostname
%ghost %config(noreplace) %{_sysconfdir}/vconsole.conf
%ghost %config(noreplace) %{_sysconfdir}/locale.conf
%ghost %config(noreplace) %{_sysconfdir}/machine-id
%ghost %config(noreplace) %{_sysconfdir}/machine-info
%ghost %config(noreplace) %{_sysconfdir}/timezone
%if %{with kdbus}
%{_sysconfdir}/X11/xinit/xinitrc.d/50-systemd-user.sh
%endif
%{_bindir}/systemd
%{_bindir}/systemctl
%{_bindir}/systemd-notify
%{_bindir}/systemd-ask-password
%{_bindir}/systemd-tty-ask-password-agent
%{_bindir}/systemd-machine-id-setup
%{_bindir}/loginctl
%{_bindir}/systemd-loginctl
%{_bindir}/journalctl
%{_bindir}/systemd-tmpfiles
%{_bindir}/systemd-nspawn
%{_bindir}/systemd-stdio-bridge
%{_bindir}/systemd-cat
%{_bindir}/systemd-cgls
%{_bindir}/systemd-cgtop
%{_bindir}/systemd-delta
%{_bindir}/systemd-detect-virt
%{_bindir}/systemd-inhibit
%{_bindir}/udevadm
%{_bindir}/systemd-escape
%{_bindir}/systemd-path
%{_prefix}/lib/sysctl.d/*.conf
%{_prefix}/lib/systemd/systemd
%{_prefix}/lib/systemd/system

%dir %{_prefix}/lib/systemd/system/basic.target.wants
%dir %{_prefix}/lib/systemd/user
%dir %{_prefix}/lib/systemd/network
%{_prefix}/lib/systemd/user/basic.target
%{_prefix}/lib/systemd/user/bluetooth.target
%{_prefix}/lib/systemd/user/exit.target
%{_prefix}/lib/systemd/user/printer.target
%{_prefix}/lib/systemd/user/shutdown.target
%{_prefix}/lib/systemd/user/sockets.target
%{_prefix}/lib/systemd/user/sound.target
%{_prefix}/lib/systemd/user/systemd-exit.service
%{_prefix}/lib/systemd/user/paths.target
%{_prefix}/lib/systemd/user/smartcard.target
%{_prefix}/lib/systemd/user/timers.target
%if %{with kdbus}
%{_prefix}/lib/systemd/user/busnames.target
%{_prefix}/lib/systemd/user/systemd-bus-proxyd.socket
%{_prefix}/lib/systemd/user/systemd-bus-proxyd.service
%endif
%exclude %{_prefix}/lib/systemd/network/80-container-ve.network
%exclude %{_prefix}/lib/systemd/network/80-container-host0.network
%{_prefix}/lib/systemd/user/default.target
%{_prefix}/lib/systemd/network/99-default.link
%exclude %{_prefix}/lib/systemd/system-preset/90-systemd.preset

%{_prefix}/lib/systemd/systemd-*
%dir %{_prefix}/lib/systemd/catalog
%{_prefix}/lib/systemd/catalog/systemd.catalog
%{_prefix}/lib/udev
%{_prefix}/lib/systemd/system-generators/systemd-efi-boot-generator
%{_prefix}/lib/systemd/system-generators/systemd-getty-generator
%{_prefix}/lib/systemd/system-generators/systemd-fstab-generator
%{_prefix}/lib/systemd/system-generators/systemd-system-update-generator
%{_prefix}/lib/systemd/system-generators/systemd-gpt-auto-generator
%if %{with kdbus}
%{_prefix}/lib/systemd/system-generators/systemd-dbus1-generator
%{_prefix}/lib/systemd/user-generators/systemd-dbus1-generator
%endif
%{_prefix}/lib/tmpfiles.d/systemd.conf
%{_prefix}/lib/tmpfiles.d/x11.conf
%{_prefix}/lib/tmpfiles.d/tmp.conf
%{_prefix}/lib/tmpfiles.d/legacy.conf
%{_prefix}/lib/tmpfiles.d/pamconsole-tmp.conf
%{_prefix}/lib/tmpfiles.d/systemd-nologin.conf
%{_prefix}/lib/tmpfiles.d/etc.conf
%{_prefix}/lib/tmpfiles.d/var.conf
%{_sbindir}/init
%{_sbindir}/reboot
%{_sbindir}/halt
%{_sbindir}/poweroff
%{_sbindir}/shutdown
%{_sbindir}/telinit
%{_sbindir}/runlevel
%{_sbindir}/udevadm
%{_datadir}/systemd/kbd-model-map
%{_datadir}/systemd/language-fallback-map
%{_datadir}/dbus-1/services/org.freedesktop.systemd1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.systemd1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.hostname1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.login1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.locale1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.timedate1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.machine1.service
%dir %{_datadir}/polkit-1
%dir %{_datadir}/polkit-1/actions
%{_datadir}/polkit-1/actions/org.freedesktop.systemd1.policy
%{_datadir}/polkit-1/actions/org.freedesktop.hostname1.policy
%{_datadir}/polkit-1/actions/org.freedesktop.login1.policy
%{_datadir}/polkit-1/actions/org.freedesktop.locale1.policy
%{_datadir}/polkit-1/actions/org.freedesktop.timedate1.policy
%{_datadir}/polkit-1/actions/org.freedesktop.machine1.policy
%dir %{_datadir}/factory/
%dir %{_datadir}/factory/etc
%dir %{_datadir}/factory/etc/pam.d
%{_datadir}/factory/etc/nsswitch.conf
%{_datadir}/factory/etc/pam.d/other
%{_datadir}/factory/etc/pam.d/system-auth

# Make sure we don't remove runlevel targets from F14 alpha installs,
# but make sure we don't create then anew.
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel2.target
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel3.target
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel4.target
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel5.target

%files -n libsystemd
%manifest %{name}.manifest
%{_libdir}/security/pam_systemd.so
%{_libdir}/libsystemd.so.*
%{_libdir}/libudev.so.*
%{_libdir}/libsystemd-daemon.so.*
%{_libdir}/libsystemd-id128.so.*
%{_libdir}/libsystemd-journal.so.*
%{_libdir}/libsystemd-login.so.*
%{_libdir}/libnss_myhostname.so.2
%{_libdir}/libnss_mymachines.so.2

%files devel
%manifest %{name}.manifest
%{_libdir}/libudev.so
%{_libdir}/libsystemd.so
%{_libdir}/libsystemd-daemon.so
%{_libdir}/libsystemd-id128.so
%{_libdir}/libsystemd-journal.so
%{_libdir}/libsystemd-login.so
%dir %{_includedir}/systemd
%if %{with kdbus}
%{_includedir}/systemd/sd-bus.h
%{_includedir}/systemd/sd-bus-protocol.h
%{_includedir}/systemd/sd-bus-vtable.h
%{_includedir}/systemd/sd-event.h
%{_includedir}/systemd/sd-path.h
%{_includedir}/systemd/sd-resolve.h
%{_includedir}/systemd/sd-rtnl.h
%{_includedir}/systemd/sd-utf8.h
%endif
%{_includedir}/systemd/_sd-common.h
%{_includedir}/systemd/sd-daemon.h
%{_includedir}/systemd/sd-id128.h
%{_includedir}/systemd/sd-journal.h
%{_includedir}/systemd/sd-login.h
%{_includedir}/systemd/sd-messages.h
%{_includedir}/libudev.h
%{_libdir}/pkgconfig/libudev.pc
%{_libdir}/pkgconfig/libsystemd.pc
%{_libdir}/pkgconfig/libsystemd-daemon.pc
%{_libdir}/pkgconfig/libsystemd-id128.pc
%{_libdir}/pkgconfig/libsystemd-journal.pc
%{_libdir}/pkgconfig/libsystemd-login.pc
%{_libdir}/pkgconfig/systemd.pc
%{_datadir}/pkgconfig/udev.pc
%{_sysconfdir}/rpm/macros.systemd

%files analyze
%manifest %{name}.manifest
%{_bindir}/systemd-analyze

%files -n libgudev
%manifest %{name}.manifest
%{_libdir}/libgudev-1.0.so.*

%files -n libgudev-devel
%manifest %{name}.manifest
%{_libdir}/libgudev-1.0.so
%dir %{_includedir}/gudev-1.0
%dir %{_includedir}/gudev-1.0/gudev
%{_includedir}/gudev-1.0/gudev/*.h
%{_libdir}/pkgconfig/gudev-1.0*

%docs_package
