use 5.008;
use strict;
use warnings;

use ExtUtils::MakeMaker;
use Getopt::Long;

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

sub MY::postamble {
    
    my $add = "
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

\$(PACKAGE)-\$(VERSION)-\$(RELEASE).src.rpm: \$(PACKAGE).spec
	test -d \$(KOLABRPMSRC)/\$(PACKAGE) || mkdir \$(KOLABRPMSRC)/\$(PACKAGE)
	cp \$(PACKAGE).spec \$(PACKAGE).spec.tmp
	sed -i -e 's/\@VERSION\@/\$(VERSION)/' \$(PACKAGE).spec.tmp
	sed -i -e 's/\@RELEASE\@/\$(RELEASE)/' \$(PACKAGE).spec.tmp
	sed -i -e 's/\@SOURCE_TAG\@/\$(SOURCE_TAG)/' \$(PACKAGE).spec.tmp
	mv \$(PACKAGE).spec.tmp \$(KOLABRPMSRC)/\$(PACKAGE)/\$(PACKAGE).spec
	mv \$(PACKAGE)-\$(SOURCE_TAG).tar.gz \$(KOLABRPMSRC)/\$(PACKAGE)
	cd \$(KOLABRPMSRC)/\$(PACKAGE) && \$(RPM) -ba \$(PACKAGE).spec
	cp -p \$(KOLABRPMPKG)/\$(PACKAGE)-\$(VERSION)-\$(RELEASE).src.rpm .

";

    return $add;
}

use lib "lib";
require "Kolab.pm";

WriteMakefile(
    NAME              => 'perl-kolab',
    VERSION           => $Kolab::VERSION,
    INSTALLDIRS       => 'vendor',
    ABSTRACT          => 
'perl-kolab provides a basic set of perl modules required for the
Kolab Groupware server.',
    AUTHOR            => 'Stuart Bingë and others (see AUTHORS file)'
    );
