# Set KOLABDIR to the base directory of the OpenPKG/Kolab installation:
KOLABDIR = $(shell openpkg rpm -q --qf '%{INSTALLPREFIX}\n' openpkg)

ifeq ($(KOLABDIR),)
  $(error Could not determine KOLABDIR!)
endif

ifeq ($(RPM),)
  RPM = $(KOLABDIR)/bin/openpkg rpm
endif
ifeq ($(KOLABRPMSRC),)
  KOLABRPMSRC = $(KOLABDIR)/RPM/SRC
endif
ifeq ($(KOLABRPMPKG),)
  KOLABRPMPKG = $(KOLABDIR)/RPM/PKG
endif
ifeq ($(KOLABRPMTMP),)
  KOLABRPMTMP = $(KOLABDIR)/RPM/TMP
endif
ifeq ($(CURSRCDIR),)
  CURSRCDIR = $(CURDIR)
endif
ifeq ($(KOLABPKGURI),)
  KOLABPKGURI = http://files.kolab.org/server/release/kolab-server-2.2.0/sources/
endif
ifeq ($(OPENPKGURI),)
  OPENPKGURI = http://files.kolab.org/server/development-2.2/openpkg-orig-srpms/
endif
ifeq ($(PLATTAG),)
  PLATTAG = $(shell $(RPM) -q --qf="%{ARCH}-%{OS}" openpkg)-$(KOLABDIR:/%=%)
endif
