use 5.008;
use strict;
use warnings;

use ExtUtils::MakeMaker;
use Getopt::Long;
use File::Copy;

my $HELP = 0;
my $CONFIG = '/skolab/etc/skolab';
my $INSTALLSCRIPT = '/skolab/bin';
my $INSTALLSBIN = '/skolab/sbin';
my $INSTALLETC = '/skolab/etc/skolab';

GetOptions(
    "config=s" => \$CONFIG,
    "bin=s" => \$INSTALLSCRIPT,
    "sbin=s" => \$INSTALLSBIN,
    "etc=s" => \$INSTALLETC,
    "help" => \$HELP
    );

if ($HELP) {
  print <<"EOH";
Usage: perl Makefile.PL [--config CONFIG_DIR] [--bin BIN_DIR] [--sbin SBIN_DIR]  [--etc ETC_DIR] --help

Option config

  to specify the path to the skolab configuration directory. The
  default is ${CONFIG} but this may vary depending on your
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

SBIN_TARGETS=sbin/skolabconf sbin/skolab_bootstrap sbin/skolab_imappartitions sbin/skolabd sbin/skolabcheckperm

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

# Upload location for the fileserver. Configure the skolab filesserver
# in your ssh config at ~/.ssh/config. E.g.:
#
# Host=skolabfiles
# User=wrobel
# Hostname=files.skolab.org
#
FILESERVER = skolabfiles

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
require "Skolab.pm";

# older versions of ExtUtils:MakeMaker don't support INSTALLVENDORSCRIPT
my $installscript = "";
if ($ExtUtils::MakeMaker::VERSION >= 6.42) {
    $installscript = "INSTALLVENDORSCRIPT";
} else {
    $installscript = "INSTALLSCRIPT";
}

WriteMakefile(
    NAME              => 'perl-skolab',
    VERSION           => $Skolab::VERSION,
    INSTALLDIRS       => 'vendor',
    EXE_FILES         => [ 'bin/skolab_smtpdpolicy',
                           'bin/skolabquotareport',
                           'bin/skolabdcachetool',
                           'bin/skolabpasswd',
                           'bin/skolabquotawarn'],
    MAN1PODS          => {
                           'bin/skolab_smtpdpolicy'     => 'blib/man1/skolab_smtpdpolicy.1p',
                           'bin/skolabquotareport'      => 'blib/man1/skolabquotareport.1p',
                           'bin/skolabdcachetool'       => 'blib/man1/skolabdcachetool.1p',
                           'bin/skolabpasswd'           => 'blib/man1/skolabpasswd.1p',
                           'bin/skolabquotawarn'        => 'blib/man1/skolabquotawarn.1p',
                           'sbin/skolab_bootstrap'      => 'blib/man1/skolab_bootstrap.1p',
                           'sbin/skolab_imappartitions' => 'blib/man1/skolab_imappartitions.1p',
                           'sbin/skolabcheckperm'       => 'blib/man1/skolabcheckperm.1p',
                           'sbin/skolabconf'            => 'blib/man1/skolabconf.1p',
                           'sbin/skolabd'               => 'blib/man1/skolabd.1p',
                         },
    $installscript    => $INSTALLSCRIPT,
    ABSTRACT          => 
'perl-skolab provides a basic set of perl modules required for the
Skolab Groupware server.',
    AUTHOR            => 'Stuart Bingë and others (see AUTHORS file)'
    );
