package Skolab::Conf;

##  COPYRIGHT
##  ---------
##
##  See AUTHORS file
##
##
##  LICENSE
##  -------
##
##  This  program is free  software; you can redistribute  it and/or
##  modify it  under the terms of the GNU  General Public License as
##  published by the  Free Software Foundation; either version 2, or
##  (at your option) any later version.
##
##  This program is  distributed in the hope that it will be useful,
##  but WITHOUT  ANY WARRANTY; without even the  implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
##  General Public License for more details.
##
##  You can view the  GNU General Public License, online, at the GNU
##  Project's homepage; see <http://www.gnu.org/licenses/gpl.html>.
##
##  $Revision$

use 5.008;
use strict;
use warnings;

use IO::File;
use File::Copy;
use File::Temp;
use File::stat;
use Skolab;
use Skolab::Util;
use Skolab::LDAP;

require Exporter;

our @ISA = qw(Exporter);

our %EXPORT_TAGS = (
    'all' => [ qw(
        &rebuildTemplates
        &checkPermissions
    ) ]
    );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(

);

my %templates = ();
my %ownership = ();
my %permissions = ();
my %confighaschanged = ();
my %commentchar = ();

sub fixup {
    my $file = shift;
    my $ownership = shift;
    my $perm = shift;

    (my $owner, my $group) = split(/:/, $ownership, 2);
    my $uid = (getpwnam($owner))[2];
    my $gid = (getgrnam($group))[2];
    Skolab::log('T', sprintf("Changing permissions of %s to 0%o", $file, $perm ), SKOLAB_DEBUG );
    if( chmod($perm, $file) != 1 ) {
        Skolab::log('T', "Unable to change permissions of `$file' to ".sprintf("0%o",$perm) . ": $!", SKOLAB_ERROR);
        exit(1);
    }
    Skolab::log('T', "Changing owner of $file to $owner:$group ($uid:$gid)", SKOLAB_DEBUG );
    if( chown($uid,$gid,$file) != 1 ) {
        Skolab::log('T', "Unable to change ownership of `$file' to $uid:$gid: $!", SKOLAB_ERROR);
        exit(1);
    }
}

sub printWarning {

    my $stream = shift;
    my $templateFile = shift;
    my $cc = shift;

    $templateFile = "" if (!defined $templateFile);
    $cc = "#" if (!defined $cc);

    # Different warnings during bootstrapping and regular configuration
    if ((defined $Skolab::config{"bootstrap_config"}) &&
        ($Skolab::config{"bootstrap_config"} eq "true")) {

        print $stream "$cc==================================================================\n";
        print $stream "$cc This is a preliminary version of this configuration file and\n";
        print $stream "$cc only used for bootstrapping.  If you see this warning in your\n";
        print $stream "$cc configuration after bootstrapping the Skolab Server\n";
        print $stream "$cc SOMETHING WENT VERY WRONG !!!\n";
        print $stream "$cc==================================================================\n";

    } else {

        print $stream "$cc==================================================================\n";
        print $stream "$cc THIS FILE IS AUTOMATICALLY WRITTEN BY THE SKOLAB CONFIG BACKEND.\n";
        print $stream "$cc MANUAL CHANGES ARE LOST UNLESS MADE IN THE TEMPLATE FILE:\n";
        print $stream "$cc\n";
        print $stream "$cc  $templateFile\n";
        print $stream "$cc\n";
        print $stream "$cc Changes can be activated by running ".$Skolab::config{'skolabconf_script'}."\n";
        print $stream "$cc==================================================================\n";

    }
}

sub build {
    my $tmpl = shift;
    my $cfg = shift;
    my $owner = shift;
    my $perm = shift;
    my $cchr = shift;  # comment character

    my $templatedir = $Skolab::config{"templatedir"};

    Skolab::log('T', "Creating new configuration file `$cfg' from template `$tmpl'", SKOLAB_DEBUG );

    my $template;
    if (!($template = IO::File->new($tmpl, 'r'))) {
        Skolab::log('T', "Unable to open template file `$tmpl': $!", SKOLAB_ERROR);
        # Error, fail gracefully
        return;
    }
    my $config;
    if (!($config = new File::Temp( TEMPLATE => 'tmpXXXXX',
                                    DIR => $Skolab::config{"skolabdir"},
                                    SUFFIX => '.skolabtmp',
                                    UNLINK => 0 ))) {
        Skolab::log('T', "Unable to open configuration file `$cfg': $!", SKOLAB_ERROR);
        exit(1);
    }

    my $skip = 0;
    my $keep = 0;
    while (<$template>) {
        #Eat the meta data sections
        if (/^SKOLAB_META_START$/) {
            my $found_end;
            while (!$found_end) {
            $_ = <$template>;
            $found_end = /^SKOLAB_META_END$/;
            }
            $_ = <$template>;
        }

        if (/\@{3}if\s+exists\(\s*(\S+?)\s*\)\@{3}/) {
            # @@@if exists(/full/path/to/file)@@@
            # also possible: @@@if exists( /full/path/to/file )@@@
            if (-f $1) {
                # Keep text if searched file or symbolic link exists.
                $keep = 1;
            } else {
                # Skip text
                $skip++;
                $keep = 0;
            }
        } elsif (/\@{3}if\s+(\S+?)\@{3}/) {
            # @@@if some_variable@@@
            # The some_variable is a key in the $Skolab::config hash and has
            # its value set to either 'false' or 'true'
            if ($Skolab::config{$1} && lc($Skolab::config{$1}) ne "false" ) {
                # Keep text
                $keep = 1;
            } else {
                # Skip text
                $skip++;
                $keep = 0;
            }
            s/\@{3}if (\S+?)\@{3}\n?//;
        } elsif (/\@{3}else\@{3}/) {
            # @@@else@@@
            if( $keep == 0 ) {
            # Now keep
            $keep = 1;
            $skip--;
            } else {
            # Now skip
            $keep = 0;
                    $skip++;
            }
                s/\@{3}else\@{3}\n?//;

        } elsif (/\@{3}endif\@{3}/) {
            # @@@endif@@@
            ($skip > 0) && $skip--;
            s/\@{3}endif\@{3}\n?//;

        } elsif (/\@{3}warning\@{3}/) {
            # @@@warning@@@
            printWarning($config, $tmpl, $cchr);

        } elsif (/\@{3}print\s+([^\s()]+?)\s*\(([^,]+)?\)\@{3}/) {
            # @@@print func([arg])@@@
            my $val;
            if ($1 eq 'getLDAPReplicas') {$val = getLDAPReplicas();}
            elsif ($1 eq 'getLDAPAccess') {$val = getLDAPAccess();}
            elsif ($1 eq 'getCyrusGroups') {$val = getCyrusGroups();}
            elsif ($1 eq 'getPostfixMap') {$val = getPostfixMap($2);}
            else {Skolab::log('T', "Unknown printable value `$1'", SKOLAB_WARN);}
            s/\@{3}print\s+(\S+?)\@{3}//;
            ($skip == 0) && print $config $val;
        } else {
            while (/\@{3}([^\s\@]+?)(\|(.+?)\((.*)\))?\@{3}/) {
                # @@@attr@@@
                # @@@attr|function(args)@@@
                my $attr = $1;
                my $fct  = $3;
                my $args = $4;
                #print STDERR "attr=\"$attr\", fct=\"$fct\", args=\"$args\"\n";
                if ($Skolab::config{$attr}) {
                    my $val = "";
                    if( !$fct ) {
                        if (ref $Skolab::config{$attr} eq "ARRAY") {
                            $val = $Skolab::config{$attr}->[0];
                        } else {
                            $val = $Skolab::config{$attr};
                        }
                    } else {
                        # Modifier functions
                        SWITCH: {
                            # Join function 
                            $fct eq 'join' && do {
                                if (ref $Skolab::config{$attr} eq "ARRAY") {
                                my @vals = @{$Skolab::config{$attr}} ;
                                # We want to make sure subdomain.domain.tld comes before domain.tld
                                my @length_sorted_vals = sort {length $b cmp length $a} @vals;
                                $val = join ($args, @length_sorted_vals) ;
                                } else {
                                $val = $Skolab::config{$attr};
                                }
                                last SWITCH;
                            };
                            # Quote function
                            $fct eq 'quote' && do {
                                # slapd.conf compatible quoting
                                $val = $Skolab::config{$attr};
                                $val =~ s/"/\"/g;
                                $val = '"'.$val.'"';
                                last SWITCH;
                            }
                        }
                    }
                    s/\@{3}([^\s\@]+?)(\|.+?)?\@{3}/$val/;
                    last if ( $val eq "\@\@\@$attr\@\@\@" ); # prevent endless loop
                } else {
                    # Only warn the user in case we are not skipping the section
                    ($skip == 0) && Skolab::log('T', "No configuration variable corresponding to `$1' exists", SKOLAB_WARN);
                    s/\@{3}([^\s\@]+?)\@{3}//;
                }
            }
            ($skip == 0) && print $config $_;
        }
    }
    
    $template->close;
    $config->close;


    if (-f $cfg) {
        my $cfgtemp = $config->filename;
        my $rc = `diff -q $cfg $cfgtemp`;
        chomp($rc);
        if ($rc) {
            Skolab::log('T', "`$cfg' change detected: $rc", SKOLAB_DEBUG );
            $confighaschanged{$tmpl} = 1;
            #making backup
            my $cfgbackup = $cfg . '.old';
            my $oldmask = umask 077;
            move($cfg, $cfgbackup) || Skolab::log('T', "Error backuping configfile to $cfgbackup, error: $!", SKOLAB_ERROR );
            # To avoid warnings, the backup files must be owned by root
            chown(0, 0, $cfgbackup);
            umask $oldmask;
        }
    } else {
        Skolab::log('T', "`$cfg' creation detected", SKOLAB_DEBUG );
        $confighaschanged{$tmpl} = 1;
    }

    if($confighaschanged{$tmpl}) {
        move($config->filename, $cfg) || Skolab::log('T', "Error moving configfile to $cfg, error: $!", SKOLAB_ERROR );
        fixup( $cfg, $owner, $perm );
    } else {
        unlink($config->filename);
    }

    Skolab::log('T', "Finished creating configuration file `$cfg'", SKOLAB_DEBUG );
}

sub getPostfixMap
{
    my $map = shift;
    my $ret = '';
    Skolab::log('T', "Building Postfix $map map", SKOLAB_DEBUG);

    my $ldap = Skolab::LDAP::create(
        $Skolab::config{'ldap_ip'},
        $Skolab::config{'ldap_port'},
        $Skolab::config{'bind_dn'},
        $Skolab::config{'bind_pw'}
    );

    my $mesg = $ldap->search(
        base    => 'k=skolab,'.$Skolab::config{'base_dn'},
        scope   => 'base',
        filter  => '(objectclass=*)'
    );
    if ($mesg->code) {
        Skolab::log('T', "Unable to locate Postfix $map map entries in LDAP", SKOLAB_ERROR);
        exit(1);
    }

    my $ldapobject;
    if ($mesg->code <= 0) {
        foreach $ldapobject ($mesg->entries) {
            my $routes = $ldapobject->get_value("postfix-$map", asref => 1);
            foreach (@$routes) {
                $_ = trim($_);
                Skolab::log('T', "Adding entry `$_' to $map");
                $ret .= $_ . "\n";
            }
        }
    } else {
        Skolab::log('T', "No Postfix $map map entries found");
    }

    Skolab::LDAP::destroy($ldap);
    Skolab::log('T', "Finished building Postfix $map map", SKOLAB_DEBUG);
    return $ret;
}

sub getCyrusGroups
{
    my $ret ='';
    Skolab::log('T', 'Building Cyrus groups', SKOLAB_DEBUG);

    my $ldap = Skolab::LDAP::create(
        $Skolab::config{'ldap_ip'},
        $Skolab::config{'ldap_port'},
        $Skolab::config{'bind_dn'},
        $Skolab::config{'bind_pw'}
    );

    my $mesg = $ldap->search(
        base    => $Skolab::config{'base_dn'},
        scope   => 'sub',
        filter  => '(&(mail=*)(objectclass=skolabgroupofnames))'
    );
    if ($mesg->code) {
        Skolab::log('T', 'Unable to locate Cyrus groups in LDAP', SKOLAB_ERROR);
        exit(1);
    }

    my $ldapobject;
    my $count = 60000;
    if ($mesg->code <= 0) {
        foreach $ldapobject ($mesg->entries) {
            #my $group = $ldapobject->get_value('cn') . '@'.join('.',reverse(@dn)) . ":*:$count:";
            my $group = lc($ldapobject->get_value('mail')).":*:$count:";
            my $userlist = $ldapobject->get_value('member', asref => 1);
            foreach (@$userlist) {
                my $uid = $_;
                my $umesg = $ldap->search( base => $uid,
                    scope => 'base', 
                    filter => '(objectClass=*)' );
                if ( $umesg && $umesg->code() <= 0 && $umesg->count() == 1 ) {
                    my $mail;
                    ($mail = $umesg->entry(0)->get_value('mail')) or
                    ($mail = $umesg->entry(0)->get_value('uid'));
                    $group .= lc($mail).',';
                }
            }
            $group =~ s/,$//;
            $ret .= $group . "\n";
            Skolab::log('T', "Adding cyrus group `$group'");
            $count++;
        }
    } else {
        Skolab::log('T', 'No Cyrus groups found');
    }

    Skolab::LDAP::destroy($ldap);

    Skolab::log('T', 'Finished building Cyrus groups', SKOLAB_DEBUG );
    return $ret;
}

sub getLDAPAccess
{
    my $ret = '';
    Skolab::log('T', 'Building LDAP access file', SKOLAB_DEBUG);


my $global_acl = <<'EOS';
# Domain specific access
access to filter=(&(objectClass=skolabInetOrgPerson)(mail=*@@@@domain@@@)(|(!(alias=*))(alias=*@@@@domain@@@)))
        by group/skolabGroupOfNames="cn=@@@domain@@@,cn=domains,cn=internal,@@@base_dn@@@" write
        by * break

access to filter=(&(objectClass=skolabGroupOfNames)(mail=*@@@@domain@@@))
        by group/skolabGroupOfNames="cn=@@@domain@@@,cn=domains,cn=internal,@@@base_dn@@@" write
        by * break

access to filter=(&(objectClass=skolabSharedFolder)(cn=*@@@@domain@@@))
        by group/skolabGroupOfNames="cn=@@@domain@@@,cn=domains,cn=internal,@@@base_dn@@@" write
        by * break

EOS

my $dom_acl1 = << 'EOS';
# Access to domain groups
access to dn.children="cn=domains,cn=internal,@@@base_dn@@@"
        by group/skolabGroupOfNames="cn=admin,cn=internal,@@@base_dn@@@" write
        by group/skolabGroupOfNames="cn=maintainer,cn=internal,@@@base_dn@@@" write
        by dn="cn=nobody,cn=internal,@@@base_dn@@@" read
EOS

my $dom_acl2 = << 'EOS';
        by group/skolabGroupOfNames="cn=@@@domain@@@,cn=domains,cn=internal,@@@base_dn@@@" read
EOS

my $dom_acl3 = << 'EOS';
         by * search stop
EOS

    my $str;
    my $domain;
    my @domains;
    if( ref($Skolab::config{'postfix-mydestination'}) eq 'ARRAY' ) {
        @domains = @{$Skolab::config{'postfix-mydestination'}};
    } else {
        @domains =( $Skolab::config{'postfix-mydestination'} );
    }

    ($str = $dom_acl1) =~ s/\@{3}base_dn\@{3}/$Skolab::config{'base_dn'}/g;
    $ret .= $str;

    foreach $domain (@domains) {
        ($str = $dom_acl2) =~ s/\@{3}domain\@{3}/$domain/g;
        $str =~ s/\@{3}base_dn\@{3}/$Skolab::config{'base_dn'}/g;
        $ret .= $str;
    }

    ($str = $dom_acl3) =~ s/\@{3}base_dn\@{3}/$Skolab::config{'base_dn'}/g;
    $ret .= $str;

    foreach $domain (@domains) {
        ($str = $global_acl) =~ s/\@{3}domain\@{3}/$domain/g;
        $str =~ s/\@{3}base_dn\@{3}/$Skolab::config{'base_dn'}/g;
        $ret .= $str;
        Skolab::log('T', "Adding acl for domain '$str'");
    }
    return $ret;
}

sub getLDAPReplicas
{
    my $ret = '';
    Skolab::log('T', 'Building LDAP replicas', SKOLAB_DEBUG);

    # directory_mode syncrepl is supported from openldap-2.3.x and beyond
    if ($Skolab::config{'directory_mode'} eq "syncrepl") {

      if ( $Skolab::config{'is_master'} eq "false" ) {
        # Output a syncrepl statement for database synchronisation
        $ret .=   "syncrepl rid=0 \n"
                 ."         provider=".$Skolab::config{"ldap_master_uri"}."\n"
                 ."         type=refreshAndPersist\n"
                 ."         retry=\"60 10 300 +\"\n"
                 ."         searchbase=\"".$Skolab::config{'base_dn'}."\"\n"
                 ."         scope=sub\n"
                 ."         schemachecking=on\n"
                 ."         binddn=\"".$Skolab::config{"bind_dn"}."\"\n"
                 ."         credentials=\"".$Skolab::config{"bind_pw"}."\"\n"
                 ."         bindmethod=simple\n";
      }

    } else {

        if( $Skolab::config{'is_master'} eq "true" ) {
            # Master setup
            my @kh;
            if( ref $Skolab::config{'skolabhost'} eq 'ARRAY' ) {
                @kh = @{$Skolab::config{'skolabhost'}};
            } else {
                @kh = ( $Skolab::config{'skolabhost'} );
            }
            for my $h ( @kh ) {
                next if lc($h) eq lc($Skolab::config{'fqdnhostname'});
                $ret .= "replica uri=ldaps://$h\n"
                ."  binddn=\"".$Skolab::config{'bind_dn'}."\"\n"
                ."  bindmethod=simple credentials=".$Skolab::config{'bind_pw'}."\n\n";
            }
        } else {
            # Slave setup
            # Output an update dn statement instead
            $ret .= "updatedn ".$Skolab::config{'bind_dn'}."\n";
            $ret .= "updateref ".$Skolab::config{'ldap_master_uri'}."\n";
        }
    }

    Skolab::log('T', 'Finished building LDAP replicas', SKOLAB_DEBUG);
    return $ret;
}

sub replaceMetaVar
{
    my $var = shift;

    while ($var =~ /\@{3}([^\s\@]+?)\@{3}/) {
        my $attr = $1;
        if ($Skolab::config{$attr}) {
            my $val = $Skolab::config{$attr};
            $var =~ s/\@{3}([^\s\@]+?)\@{3}/$val/;
        } else {
            Skolab::log('T', "No configuration variable corresponding to `$1' exists", SKOLAB_WARN);
        }
    }
    return $var;
}


sub loadMetaTemplates
{
    my $templatedir = shift;
    my ($tref, $pref, $oref, $cmdref, $ccharref) = @_;

    Skolab::log('T', 'Collecting template files', SKOLAB_DEBUG );
    opendir(DIR, $templatedir) or Skolab::log('T', 'Given templatedir $templatedir does not exist!', SKOLAB_ERROR );
    my @metatemplates = grep { /\.template$/ } readdir (DIR);
    closedir(DIR);

    foreach my $template (@metatemplates) {
        my $runonchange = undef;
        my $commentchar = undef;
        #Open each file and check for the META
        if (open (TEMPLATE, "$templatedir/$template" )) {
            my $line = <TEMPLATE>;
            if ($line =~ /^SKOLAB_META_START$/) {
                Skolab::log('T', 'Processing META template :'.$template, SKOLAB_DEBUG );
                my ($found_end, $target, $permissions, $ownership);
                while (<TEMPLATE>) {
                    $line = $_;
                    
                    if (!$found_end) {
                        $found_end = $line =~ /^SKOLAB_META_END$/;
                        if (!$found_end && $line) {
                            my ($key,$value) = split(/=/,$line);
                            chomp($value);
                            Skolab::log('T', 'META Key: '.$key.' Value: '.$value, SKOLAB_DEBUG );
                            if ($key =~ /^TARGET$/) {
                                $target = replaceMetaVar($value);
                                Skolab::log('T', 'META Target '.$target, SKOLAB_DEBUG );
                            } elsif ($key =~ /^PERMISSIONS$/) {
                                $permissions = replaceMetaVar($value);
                                Skolab::log('T', 'META Permissions '.$permissions, SKOLAB_DEBUG );
                            } elsif ($key =~ /^OWNERSHIP$/) {
                                $ownership = replaceMetaVar($value);
                                Skolab::log('T', 'META Ownership '.$ownership, SKOLAB_DEBUG );
                            } elsif ($key =~ /^RUNONCHANGE$/) {
                                $runonchange = replaceMetaVar($value);
                                Skolab::log('T', 'META Cmd to execute '.$runonchange, SKOLAB_DEBUG );
                            } elsif ($key =~ /^COMMENT_CHAR$/) {
                                $commentchar = replaceMetaVar($value);
                                Skolab::log('T', 'META CommentChar to use: '.$commentchar, SKOLAB_DEBUG );
                            } else {
                                Skolab::log('T', 'incorrect META key "'.$key.'" in: '.$template, SKOLAB_WARN );
                            }
                        }
                    }
                }
                if ($found_end && $target && $permissions && $ownership) {
                    Skolab::log('T', 'All mandatory fields populated in '.$template, SKOLAB_DEBUG );
                    $$tref{$templatedir . "/" . $template} = $target;
                    $$oref{$target} = $ownership;
                    $permissions = oct($permissions);
                    $$pref{$target} = $permissions;
                    my $runcmdtemplate = $templatedir."/".$template;
                    $$cmdref{$runcmdtemplate} = $runonchange if (defined $runonchange);
                    $$ccharref{$target} = $commentchar if (defined $commentchar);
                }
            }
        } else {
            Skolab::log('T', 'Could not open template file: '. $template, SKOLAB_WARN);
        }
    }

}

sub rebuildTemplates
{
    my %args = @_;
    $args{doreload} = 1 if !exists $args{doreload};
    $args{dorunonchange} = 1 if !exists $args{dorunonchange};
    #$args{templates} = ALL if !exists $args{templates};

    my $key;
    my $value;
    my $section="";
    my %runonchange;

    my $templatedir = $Skolab::config{"templatedir"};

    Skolab::log('T', 'Regenerating configuration files', SKOLAB_DEBUG );

    Skolab::log('T', 'Loading meta-template data', SKOLAB_DEBUG );
    loadMetaTemplates( $templatedir, \%templates, \%permissions, \%ownership, \%runonchange, \%commentchar );

    # defaults to all templates
    $args{templates} = [ keys %templates ] if !exists $args{templates};
    my $cfg;
    my $tpl;
    foreach $tpl (@{$args{templates}}) {
        $cfg = $templates{$tpl};
        build($tpl, $cfg, $ownership{$cfg}, $permissions{$cfg}, $commentchar{$cfg});
     }

    Skolab::log('T', 'Finished regenerating configuration files', SKOLAB_DEBUG );

    if(!$args{dorunonchange}) {
        Skolab::log('T', 'RUNONCHANGE will not be executed, as requested.', SKOLAB_DEBUG );
        return;
    }

    my %cmds = ();
    foreach $key (keys %runonchange) {
        if (defined $confighaschanged{$key}) {
            Skolab::log('T', 'Queueing RUNONCHANGE for '.$key, SKOLAB_DEBUG );
            $cmds{$runonchange{$key}} = 1;
        }
    }
    my $cmd;
    foreach $cmd (keys %cmds) {
        # $cmd can contain:
        # - /usr/sbin/postmap: should always be executed
        # - openpkg rc imapd restart (in openpkg distribution)
        # - skolabsrv rc post reload  (in other distributions)
        # The commands with ' rc ' may only be executed when reloading is not
        # prohibited by the user with the "-n" option.
        if ($args{doreload} || $cmd !~ / rc \S+ re(start|load)/) {
            Skolab::log('T', 'Executing command: '.$cmd, SKOLAB_DEBUG );
            system($cmd);
        } else {
            Skolab::log('T', 'Reload not allowed, not executing command: '.$cmd, SKOLAB_DEBUG );
        }
    }
}

sub checkPermissions {
    my $key;
    my $value;

    my $templatedir = $Skolab::config{"templatedir"};

    Skolab::log('T', 'Checking generated config file permissions and ownership', SKOLAB_DEBUG );

    loadMetaTemplates( $templatedir, \%templates, \%permissions, \%ownership );

    my $ok = 1;

    foreach $key (keys %templates) {
        my $tpl = $templates{$key};

        if (-r $tpl) {
            my $st = stat($tpl);
            my $owner = getpwuid($st->uid).':'.getgrgid($st->gid);
            if( ( ($st->mode & 07777) != $permissions{$tpl}) ||
                    ($owner ne $ownership{$tpl}) ) {
                my $str = 'File '.$tpl.' has the wrong persmissions/owner. Found '
                    .sprintf("%lo", $st->mode&07777).' '.$owner.', expected '
                    .sprintf("%lo",$permissions{$tpl}).' '.$ownership{$tpl};
                print( "$str\n" );
                Skolab::log('T', $str, SKOLAB_ERROR );
                $ok = 0;
            }
        } else {
            my $str = "File $tpl does not exist";
            print "$str\n";
            Skolab::log('T', "$str", SKOLAB_ERROR );
        }
    }
    return $ok;
}

1;
__END__
=head1 NAME

Skolab::Conf - Perl extension for Skolab template generation

=head1 ABSTRACT

  Skolab::Conf handles the generation of template files, used by
  skolabconf.

=head1 COPYRIGHT AND AUTHORS

Stuart Bingë and others (see AUTHORS file)

=head1 LICENSE

This  program is free  software; you can redistribute  it and/or
modify it  under the terms of the GNU  General Public License as
published by the  Free Software Foundation; either version 2, or
(at your option) any later version.

This program is  distributed in the hope that it will be useful,
but WITHOUT  ANY WARRANTY; without even the  implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
General Public License for more details.

You can view the  GNU General Public License, online, at the GNU
Project's homepage; see <http://www.gnu.org/licenses/gpl.html>.

=cut
