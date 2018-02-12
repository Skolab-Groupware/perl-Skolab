use 5.008;
use strict;
use warnings;

use ExtUtils::MakeMaker;
use Getopt::Long;
use File::Copy;

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
    my $add = "
bin/%: bin/%.in
	cat \$< | sed -e 's#\@CONFIG_DIR@#$CONFIG#g' > \$@

sbin/%: sbin/%.in
	cat \$< | sed -e 's#\@CONFIG_DIR@#$CONFIG#g' > \$@.tmp
	cat \$@.tmp | sed -e 's#\@VERSION@#\$(VERSION)#g' > \$@
	rm \$@.tmp
	\$(FIXIN) \$@

SBIN_TARGETS=sbin/kolabconf sbin/kolab_bootstrap sbin/kolab_imappartitions sbin/kolabd sbin/kolabcheckperm

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

# Upload location for the fileserver. Configure the kolab filesserver
# in your ssh config at ~/.ssh/config. E.g.:
#
# Host=kolabfiles
# User=wrobel
# Hostname=files.kolab.org
#
FILESERVER = kolabfiles

# Short name for uploading the snapshot.
.PHONY:snapshot
snapshot: .sent-\$(DISTVNAME).tar\$(SUFFIX)

# Indicator to avoid uploading the same package twice.
.sent-\$(DISTVNAME).tar\$(SUFFIX): \$(DISTVNAME).tar\$(SUFFIX)
	echo \"put \$(DISTVNAME).tar\$(SUFFIX)\" | sftp \$(FILESERVER)
	touch .sent-\$(DISTVNAME).tar\$(SUFFIX)
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
    VERSION           => $Skolab::VERSION,
    INSTALLDIRS       => 'vendor',
    EXE_FILES         => [ 'bin/kolab_smtpdpolicy',
                           'bin/kolabquotareport',
                           'bin/kolabdcachetool',
                           'bin/kolabpasswd',
                           'bin/kolabquotawarn'],
    MAN1PODS          => {
                           'bin/kolab_smtpdpolicy'     => 'blib/man1/kolab_smtpdpolicy.1p',
                           'bin/kolabquotareport'      => 'blib/man1/kolabquotareport.1p',
                           'bin/kolabdcachetool'       => 'blib/man1/kolabdcachetool.1p',
                           'bin/kolabpasswd'           => 'blib/man1/kolabpasswd.1p',
                           'bin/kolabquotawarn'        => 'blib/man1/kolabquotawarn.1p',
                           'sbin/kolab_bootstrap'      => 'blib/man1/kolab_bootstrap.1p',
                           'sbin/kolab_imappartitions' => 'blib/man1/kolab_imappartitions.1p',
                           'sbin/kolabcheckperm'       => 'blib/man1/kolabcheckperm.1p',
                           'sbin/kolabconf'            => 'blib/man1/kolabconf.1p',
                           'sbin/kolabd'               => 'blib/man1/kolabd.1p',
                         },
    $installscript    => $INSTALLSCRIPT,
    ABSTRACT          => 
'perl-kolab provides a basic set of perl modules required for the
Kolab Groupware server.',
    AUTHOR            => 'Stuart Bingë and others (see AUTHORS file)'
    );
