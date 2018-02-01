EXTRA_DIST =
CLEANFILES =

@distribution@
@common@

# Work around to autoconf's deficiencies
distclean-local:
	rm -rf $(srcdir)/autom4te*.cache

noinst_HEADERS = @PACKAGE@.spec

perl_kolabdir = $(perllib)
perl_kolab_DATA = Kolab/Kolab.pm

perl_modulesdir = $(perllib)/Kolab
perl_modules_DATA = Kolab-Conf/Conf.pm \
	Kolab-Cyrus/Cyrus.pm \
	Kolab-DirServ/DirServ.pm \
	Kolab-LDAP/LDAP.pm \
	Kolab-Mailer/Mailer.pm \
	Kolab-Util/Util.pm

EXTRA_DIST += Kolab-Cyrus/Cyrus.pm \
	Kolab-Util/Util.pm


backenddir = $(perl_modulesdir)/LDAP
dist_backend_DATA = Kolab-LDAP-Backend/Backend.pm

	
LDAP_module_FILES = Kolab-LDAP-Backend-ad/ad.pm \
	Kolab-LDAP-Backend-dirservd/dirservd.pm \
	Kolab-LDAP-Backend-slurpd/slurpd.pm

LDAP_moduledir = $(backenddir)/Backend
LDAP_module_DATA = $(LDAP_module_FILES)

EXTRA_DIST += Kolab-LDAP-Backend/Backend.pm \
	Kolab-LDAP-Backend-ad/ad.pm \
	Kolab-LDAP-Backend-dirservd/dirservd.pm

pkdocdir = $(pkgdocdir)/perl-kolab
dist_pkdoc_DATA = ChangeLog NEWS AUTHORS COPYING
EXTRA_DIST += INSTALL

Kolab/Kolab.pm:
	@$(mkinstalldirs) Kolab
	$(do_subst) <$(srcdir)/Kolab/Kolab.pm.in > $@
CLEANFILES += Kolab/Kolab.pm
EXTRA_DIST += Kolab/Kolab.pm.in

Kolab-Conf/Conf.pm:
	@$(mkinstalldirs) Kolab-Conf
	$(do_subst) <$(srcdir)/Kolab-Conf/Conf.pm.in > $@
CLEANFILES += Kolab-Conf/Conf.pm
EXTRA_DIST += Kolab-Conf/Conf.pm.in

Kolab-DirServ/DirServ.pm:
	@$(mkinstalldirs) Kolab-DirServ
	$(do_subst) <$(srcdir)/Kolab-DirServ/DirServ.pm.in > $@
CLEANFILES += Kolab-DirServ/DirServ.pm
EXTRA_DIST += Kolab-DirServ/DirServ.pm.in

Kolab-LDAP/LDAP.pm:
	@$(mkinstalldirs) Kolab-LDAP
	$(do_subst) <$(srcdir)/Kolab-LDAP/LDAP.pm.in > $@
CLEANFILES += Kolab-LDAP/LDAP.pm
EXTRA_DIST += Kolab-LDAP/LDAP.pm.in

Kolab-LDAP-Backend-slurpd/slurpd.pm:
	@$(mkinstalldirs) Kolab-LDAP-Backend-slurpd
	$(do_subst) <$(srcdir)/Kolab-LDAP-Backend-slurpd/slurpd.pm.in > $@
CLEANFILES += Kolab-LDAP-Backend-slurpd/slurpd.pm
EXTRA_DIST += Kolab-LDAP-Backend-slurpd/slurpd.pm.in

Kolab-Mailer/Mailer.pm:
	@$(mkinstalldirs) Kolab-Mailer
	$(do_subst) <$(srcdir)/Kolab-Mailer/Mailer.pm.in > $@
CLEANFILES += Kolab-Mailer/Mailer.pm
EXTRA_DIST += Kolab-Mailer/Mailer.pm.in

CLEANFILES += perl-kolab.spec

EXTRA_DIST += dist_conf/common \
	dist_conf/debian \
	dist_conf/gentoo \
	dist_conf/kolab \
	dist_conf/mandriva \
	dist_conf/suse


