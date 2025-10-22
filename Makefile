PKG      := kylin-ai-cryptojacking-detect
PKG_US   := $(subst -,_,$(PKG))
TOPDIR   ?= $(PWD)/.rpmbuild

.PHONY: sdist rpm srpm clean

sdist:
	python3 -m build --sdist

rpm: sdist
	mkdir -p $(TOPDIR)/SOURCES
	if ls dist/$(PKG)-*.tar.gz >/dev/null 2>&1; then \
	  cp dist/$(PKG)-*.tar.gz $(TOPDIR)/SOURCES/; \
	else \
	  cp dist/$(PKG_US)-*.tar.gz $(TOPDIR)/SOURCES/; \
	fi
	rpmbuild -ba packaging/$(PKG).spec --define "_topdir $(TOPDIR)"

srpm: sdist
	mkdir -p $(TOPDIR)/SOURCES
	if ls dist/$(PKG)-*.tar.gz >/dev/null 2>&1; then \
	  cp dist/$(PKG)-*.tar.gz $(TOPDIR)/SOURCES/; \
	else \
	  cp dist/$(PKG_US)-*.tar.gz $(TOPDIR)/SOURCES/; \
	fi
	rpmbuild -bs packaging/$(PKG).spec --define "_topdir $(TOPDIR)"

clean:
	rm -rf dist build *.egg-info .rpmbuild
