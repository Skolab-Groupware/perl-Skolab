use 5.008;
use strict;
use warnings;

use ExtUtils::MakeMaker;
use Getopt::Long;

my $HELP = 0;
my $CONFIG = '/kolab/etc/kolab';
my $INSTALLSCRIPT = '/kolab/bin';
my $INSTALLSBIN = '/kolab/sbin';
my $INSTALLETC = '/kolab/etc/kolab';

GetOptions(
    "config=s" => \$CONFIG,
    "bin=s" => \$INSTALLSCRIPT,
    "sbin=s" => \$INSTALLSBIN,
    "etc=s" => \$INSTALLETC,
    "help" => \$HELP
    );

if ($HELP) {
  print <<'EOH';
Usage: perl Makefile.PL [--config CONFIG_DIR] [--bin BIN_DIR] [--sbin SBIN_DIR]  [--etc ETC_DIR] --help

Option config

  to specify the path to the kolab configuration directory. The
  default is /kolab/etc/kolab/ but this may vary depending on your
  installation.

Option bin

  to specify the path to the directory where scripts should be installed.

Option sbin

  to specify the path to the directory where admin scripts should be installed.

Option etc

  to specify the path to the configuration directory.

Option help

  to get this text.

EOH
exit 0;
}

# Add the dist_openpkg target to the dist target
sub MY::dist {
    package MY;   # To help SUPER work right
    my $self = shift;
    my @m;
    
    push(@m, $self->SUPER::dist(@_));
    
    my $dist = join "", @m;

    $dist =~ s/(tardist.*)/clean_tardist $1 dist_openpkg/;
     
    return $dist;
}

# Remove additional files
sub MY::veryclean {
    package MY;   # To help SUPER work right
    my $self = shift;
    my @m;
    
    push(@m, $self->SUPER::clean(@_));
    
    my $clean = join "", @m;

    $clean =~ s/(clean.*)/$1 clean_openpkg clean_scripts/;
     
    return $clean;
}

# Install sbin files
sub MY::install {
    package MY;   # To help SUPER work right
    my $self = shift;
    my @m;
    
    push(@m, $self->SUPER::install(@_));
    
    my $install = join "", @m;

    $install =~ s/(install.*)/$1 install_sbin install_etc/;
     
    return $install;
}

sub MY::postamble {
    
    my $add = "bin/%: bin/%.in
	cat \$< | sed -e 's#\@CONFIG_DIR@#$CONFIG#g' > \$@

sbin/%: sbin/%.in
	cat \$< | sed -e 's#\@CONFIG_DIR@#$CONFIG#g' > \$@
	\$(FIXIN) \$@

SBIN_TARGETS=sbin/kolabconf sbin/kolab_bootstrap sbin/kolabd sbin/kolabcheckperm

install_sbin: \$(SBIN_TARGETS)
	mkdir -p \$(DESTDIR)/$INSTALLSBIN
	for SBIN in \$(SBIN_TARGETS); do               \\
	  cp \$\$SBIN \$(DESTDIR)/$INSTALLSBIN;        \\
	done
	chmod 755 \$(DESTDIR)/$INSTALLSBIN/*

install_etc:
	mkdir -p \$(DESTDIR)/$INSTALLETC
	for ETC in data/etc/*; do                    \\
	  cp \$\$ETC \$(DESTDIR)/$INSTALLETC;        \\
	done

ifeq \"x\$(RPM)\" \"x\"
  RPM = \$(HOME)/bin/openpkg rpm
endif
ifeq \"x\$(KOLABRPMSRC)\" \"x\"
  KOLABRPMSRC = \$(HOME)/RPM/SRC
endif
ifeq \"x\$(KOLABRPMPKG)\" \"x\"
  KOLABRPMPKG = \$(HOME)/RPM/PKG
endif
ifeq \"x\$(KOLABRPMTMP)\" \"x\"
  KOLABRPMTMP = \$(HOME)/RPM/TMP
endif

ifeq \"x\$(PLATTAG)\" \"x\"
	PLATTAG = \$(shell \$(RPM) -q --qf=\"%{ARCH}-%{OS}\" openpkg)-\$(HOME:/%=%)
endif

PACKAGE = \$(shell [ -r \"perl-kolab.spec\" ] && grep '%define[ ]*V_package' perl-kolab.spec | sed -e 's/.*V_package\\s*\\([a-z\\_-]*\\).*/\\1/')
VERSION = \$(shell perl -I lib -e 'use Kolab;print \$\$Kolab::KOLAB_VERSION;')
RELEASE = \$(shell perl -I lib -e 'use Kolab;print \$\$Kolab::KOLAB_RELEASE;')
SOURCE_TAG = \$(shell perl -I lib -e 'use Kolab;print \$\$Kolab::VERSION;')

clean_tardist:
	rm -rf *.tar.gz

clean_all: clean_tardist veryclean
	rm -rf \$(KOLABRPMTMP)/\$(PACKAGE)
	rm -rf *.src.rpm
	rm -rf *~

dist_openpkg: perl-kolab.spec \$(PACKAGE)-\$(VERSION)-\$(RELEASE).src.rpm
	cp \$(PACKAGE)-\$(VERSION)-\$(RELEASE).src.rpm ../stage/

\$(KOLABRPMPKG)/\$(PACKAGE)-\$(VERSION)-\$(RELEASE).\$(PLATTAG).rpm \$(PACKAGE)-\$(VERSION)-\$(RELEASE).src.rpm: \$(PACKAGE).spec
	test -d \$(KOLABRPMSRC)/\$(PACKAGE) || mkdir \$(KOLABRPMSRC)/\$(PACKAGE)
	cp \$(PACKAGE).spec \$(PACKAGE).spec.tmp
	sed -i -e 's/\@VERSION\@/\$(VERSION)/' \$(PACKAGE).spec.tmp
	sed -i -e 's/\@RELEASE\@/\$(RELEASE)/' \$(PACKAGE).spec.tmp
	sed -i -e 's/\@SOURCE_TAG\@/\$(SOURCE_TAG)/' \$(PACKAGE).spec.tmp
	mv \$(PACKAGE).spec.tmp \$(KOLABRPMSRC)/\$(PACKAGE)/\$(PACKAGE).spec
	mv \$(PACKAGE)-\$(SOURCE_TAG).tar.gz \$(KOLABRPMSRC)/\$(PACKAGE)
	cd \$(KOLABRPMSRC)/\$(PACKAGE) && \$(RPM) -ba \$(PACKAGE).spec
	cp -p \$(KOLABRPMPKG)/\$(PACKAGE)-\$(VERSION)-\$(RELEASE).src.rpm .

.PHONY: install-kolab
install-kolab: \$(KOLABRPMPKG)/\$(PACKAGE)-\$(VERSION)-\$(RELEASE).\$(PLATTAG).rpm
	\$(RPM) -Uhv --force \$(KOLABRPMPKG)/\$(PACKAGE)-\$(VERSION)-\$(RELEASE).\$(PLATTAG).rpm
";

    return $add;
}

use lib "lib";
require "Kolab.pm";

# older versions of ExtUtils:MakeMaker don't support INSTALLVENDORSCRIPT
my $installscript = "";
if ($ExtUtils::MakeMaker::VERSION >= 6.42) {
    $installscript = "INSTALLVENDORSCRIPT";
} else {
    $installscript = "INSTALLSCRIPT";
}

WriteMakefile(
    NAME              => 'perl-kolab',
    VERSION           => $Kolab::VERSION,
    INSTALLDIRS       => 'vendor',
    EXE_FILES         => [ 'bin/kolab_smtpdpolicy',
                           'bin/kolabquotareport',
                           'bin/kolabdcachetool',
                           'bin/kolabpasswd',
                           'bin/kolabquotawarn'],
    MAN1PODS          => {
                           'bin/kolab_smtpdpolicy' => 'blib/man1/kolab_smtpdpolicy.1p',
                           'bin/kolabquotareport'  => 'blib/man1/kolabquotareport.1p',
                           'bin/kolabdcachetool'   => 'blib/man1/kolabdcachetool.1p',
                           'bin/kolabpasswd'       => 'blib/man1/kolabpasswd.1p',
                           'bin/kolabquotawarn'    => 'blib/man1/kolabquotawarn.1p',
                           'sbin/kolab_bootstrap'  => 'blib/man1/kolab_bootstrap.1p',
                           'sbin/kolabcheckperm'   => 'blib/man1/kolabcheckperm.1p',
                           'sbin/kolabconf'        => 'blib/man1/kolabconf.1p',
                           'sbin/kolabd'           => 'blib/man1/kolabd.1p',
                         },
    $installscript    => $INSTALLSCRIPT,
    ABSTRACT          => 
'perl-kolab provides a basic set of perl modules required for the
Kolab Groupware server.',
    AUTHOR            => 'Stuart Bingë and others (see AUTHORS file)'
    );
