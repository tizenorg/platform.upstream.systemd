install:
	install -m 0644 platform-restart.target $(DESTDIR)/usr/lib/systemd/system
	install -m 0644 pr-action.target $(DESTDIR)/usr/lib/systemd/system
	install -m 0644 pr-custom.target $(DESTDIR)/usr/lib/systemd/system
	install -m 0644 platform-restart.service $(DESTDIR)/usr/lib/systemd/system
	install -m 0644 do-return.service $(DESTDIR)/usr/lib/systemd/system
	install -m 0644 cleanup-tmp.service $(DESTDIR)/usr/lib/systemd/system

symlinks:
	mkdir -p $(DESTDIR)/usr/lib/systemd/system/platform-restart.target.requires
	mkdir -p $(DESTDIR)/usr/lib/systemd/system/platform-restart.service.requires
	mkdir -p $(DESTDIR)/usr/lib/systemd/system/pr-action.target.wants
	ln -s  ../platform-restart.service $(DESTDIR)/usr/lib/systemd/system/platform-restart.target.requires/platform-restart.service
	ln -s ../shutdown.target $(DESTDIR)/usr/lib/systemd/system/platform-restart.service.requires/shutdown.target
	ln -s ../pr-custom.target $(DESTDIR)/usr/lib/systemd/system/pr-action.target.wants/pr-custom.target
	ln -s ../cleanup-tmp.service $(DESTDIR)/usr/lib/systemd/system/pr-action.target.wants/cleanup-tmp.service
	ln -s ../do-return.service $(DESTDIR)/usr/lib/systemd/system/pr-action.target.wants/do-return.service

all: install symlinks

.PHONY: install symlinks all
