package Kolab::Conf;

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
##  $Revision: 1.4 $

use 5.008;
use strict;
use warnings;

use IO::File;
use File::Copy;
use File::Temp;
use File::stat;
use Kolab;
use Kolab::Util;
use Kolab::LDAP;

require Exporter;

our @ISA = qw(Exporter);

our %EXPORT_TAGS = (
    'all' => [ qw(
        &buildPostfixTransportMap
        &buildCyrusGroups
        &buildLDAPReplicas
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
my %templatehaschanged = ();
my %haschanged = ();
my %commentchar = ();

sub fixup {
    my $file = shift;
    my $ownership = shift;
    my $perm = shift;

    (my $owner, my $group) = split(/:/, $ownership, 2);
    my $uid = (getpwnam($owner))[2];
    my $gid = (getgrnam($group))[2];
    Kolab::log('T', sprintf("Changing permissions of %s to 0%o", $file, $perm ), KOLAB_DEBUG );
    if( chmod($perm, $file) != 1 ) {
	Kolab::log('T', "Unable to change permissions of `$file' to ".sprintf("0%o",$perm) . ": $!", KOLAB_ERROR);
	exit(1);
    }
    Kolab::log('T', "Changing owner of $file to $owner:$group ($uid:$gid)", KOLAB_DEBUG );
    if( chown($uid,$gid,$file) != 1 ) {
	Kolab::log('T', "Unable to change ownership of `$file' to $uid:$gid: $!", KOLAB_ERROR);
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
# $Kolab::config{"bootstrap_config"} = "true";
    if ((defined $Kolab::config{"bootstrap_config"}) &&
        ($Kolab::config{"bootstrap_config"} eq "true")) {

        print $stream "$cc=================================================================\n";
        print $stream "$cc This is a preliminary version of this configuration file and\n";
        print $stream "$cc only used for bootstrapping.  If you see this warning in your\n";
        print $stream "$cc configuration after bootstrapping the Kolab Server\n";
        print $stream "$cc SOMETHING WENT VERY WRONG !!!\n";
        print $stream "$cc=================================================================\n";

    } else {

        print $stream "$cc=================================================================\n";
        print $stream "$cc THIS FILE IS AUTOMATICALLY WRITTEN BY THE KOLAB CONFIG BACKEND.\n";
        print $stream "$cc MANUAL CHANGES ARE LOST UNLESS MADE IN THE TEMPLATE FILE:\n";
        print $stream "$cc\n";
        print $stream "$cc  $templateFile\n";
        print $stream "$cc\n";
        print $stream "$cc Changes can be activated by running ".$Kolab::config{'kolabconf_script'}."\n";
        print $stream "$cc=================================================================\n";

    }
}

sub build {
    my $tmpl = shift;
    my $cfg = shift;
    my $owner = shift;
    my $perm = shift;
    my $cchr = shift;  # comment character

    my $oldcfg = $cfg . '.old';
    my $templatedir = $Kolab::config{"templatedir"};

    my %special_templates = (
	"$templatedir/transport.template"      => 1,
	"$templatedir/virtual.template"        => 1,
	"$templatedir/imapd.group.template"    => 1,
	"$templatedir/slapd.access.template"   => 1,
	"$templatedir/slapd.replicas.template" => 1
	);

    my $oldmask = umask 077;
    #creating the config file is changing it
    if (! -f $cfg) { 
        $templatehaschanged{$tmpl} = 1;
        Kolab::log('T', "`$cfg' creation detected", KOLAB_DEBUG );
    }
    copy($cfg, $oldcfg);
    #chown($Kolab::config{'kolab_uid'}, $Kolab::config{'kolab_gid'}, $oldcfg);
    # To avoid warnings, the backup files must be owned by root
    chown(0, 0, $oldcfg);
    umask $oldmask;
    #chmod(0600, $oldcfg) if ($oldcfg =~ /openldap/);

    Kolab::log('T', "Creating new configuration file `$cfg' from template `$tmpl'", KOLAB_DEBUG );
    #print STDERR "Creating new configuration file `$cfg' from template `$tmpl'\n";

    my $template;
    if (!($template = IO::File->new($tmpl, 'r'))) {
        Kolab::log('T', "Unable to open template file `$tmpl': $!", KOLAB_ERROR);
	# Error, fail gracefully
	return;
    }
    my $config;
    if (!($config = new File::Temp( TEMPLATE => 'tmpXXXXX',
				    DIR => $Kolab::config{"kolabdir"},
				    SUFFIX => '.kolabtmp',
				    UNLINK => 0 ))) {
        Kolab::log('T', "Unable to open configuration file `$cfg': $!", KOLAB_ERROR);
        exit(1);
    }

    #Kolab::log('T', "Using temporary file '".$config->filename."'", KOLAB_DEBUG );

    my $skip = 0;
    my $keep = 0;
    while (<$template>) {
    	#Eat the meta data sections
	if (/^KOLAB_META_START$/) {
	    my $found_end;
	    while (!$found_end) {	
		$_ = <$template>;
		$found_end = /^KOLAB_META_END$/;
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
            # The some_variable is a key in the $Kolab::config hash and has
            # its value set to either 'false' or 'true'
            if ($Kolab::config{$1} && lc($Kolab::config{$1}) ne "false" ) {
                # Keep text
		$keep = 1;
            } else {
                # Skip text
                $skip++;
		$keep = 0;
            }
            s/\@{3}if (\S+?)\@{3}\n?//;
	} elsif (/\@{3}else\@{3}/) {
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
            ($skip > 0) && $skip--;
            s/\@{3}endif\@{3}\n?//;

        } elsif (/\@{3}warning\@{3}/) { 

            printWarning($config, $tmpl, $cchr);

        } else {
            while (/\@{3}([^\s\@]+?)(\|(.+?)\((.*)\))?\@{3}/) {
		my $attr = $1;
		my $fct  = $3;
		my $args = $4;
		#print STDERR "attr=\"$attr\", fct=\"$fct\", args=\"$args\"\n";
		if ($Kolab::config{$attr}) {
		    my $val = "";
		    if( !$fct ) {
			if (ref $Kolab::config{$attr} eq "ARRAY") {
			    $val = $Kolab::config{$attr}->[0];
			} else {
			    $val = $Kolab::config{$attr};
			}
		    } else {
			# Modifier functions
		      SWITCH: {
			  # Join function 
			  $fct eq 'join' && do {
			      if (ref $Kolab::config{$attr} eq "ARRAY") {
				  my @vals = @{$Kolab::config{$attr}} ;
				  # We want to make sure subdomain.domain.tld comes before domain.tld
				  my @length_sorted_vals = sort {length $b cmp length $a} @vals;
				  $val = join ($args, @length_sorted_vals) ;
			      } else {
				  $val = $Kolab::config{$attr};
			      }
			      last SWITCH;
			  };
			  # Quote function
			  $fct eq 'quote' && do {
			      # slapd.conf compatible quoting
			      $val = $Kolab::config{$attr};
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
		    ($skip == 0) && Kolab::log('T', "No configuration variable corresponding to `$1' exists", KOLAB_WARN);
		    s/\@{3}([^\s\@]+?)\@{3}//;
		}
	    }
	    ($skip == 0) && print $config $_;
	}
    }
    
    $template->close;
    $config->close;

    move($config->filename, $cfg) || Kolab::log('T', "Error moving configfile to $cfg, error: $!", KOLAB_ERROR );
    fixup( $cfg, $owner, $perm );
    #chown($Kolab::config{'kolab_uid'}, $Kolab::config{'kolab_gid'}, $cfg);
    #chmod(0600, $cfg) if ($cfg =~ /openldap/);

    if (-f $oldcfg && !defined $special_templates{$tmpl} ) {
        my $rc = `diff -q $cfg $oldcfg`;
        chomp($rc);
        if ($rc) {
            if ($cfg =~ /postfix/) {
                $haschanged{'postfix'} = 1;
            } elsif ($cfg =~ /saslauthd/) {
                $haschanged{'saslauthd'} = 1;
            } elsif ($cfg =~ /apache/) {
                $haschanged{'apache'} = 1;
            } elsif ($cfg =~ /openldap/) {
                $haschanged{'slapd'} = 1;
            } elsif ($cfg =~ /imapd/) {
                $haschanged{'imapd'} = 1;
	    } elsif ($cfg =~ /amavisd/) {
                $haschanged{'amavisd'} = 1;
	    } elsif ($cfg =~ /clamav/) {
                $haschanged{'clamav'} = 1;
#} elsif ($cfg =~ /example/) {
	    } else {
		Kolab::log('T', "`$cfg' change detected ", KOLAB_DEBUG );
	    }
	    $templatehaschanged{$tmpl} = 1;

            Kolab::log('T', "`$cfg' change detected: $rc", KOLAB_DEBUG );
        }
    }

    Kolab::log('T', "Finished creating configuration file `$cfg'", KOLAB_DEBUG );
}

sub buildPostfixTransportMap
{
    buildPostfixMap( 'transport' );
}

sub buildPostfixVirtualMap
{
    buildPostfixMap( 'virtual' );
}

sub buildPostfixMap
{
    my $map = shift;
    Kolab::log('T', "Building Postfix $map map", KOLAB_DEBUG);

    my $templatedir = $Kolab::config{"templatedir"};

    my $keytemplate = "$templatedir/$map.template";
    my $cfg = $templates{$keytemplate};
    my $oldcfg = $cfg . '.old';

    #my $oldmask = umask 077;
    #copy($cfg, $oldcfg);
    #chown($Kolab::config{'kolab_uid'}, $Kolab::config{'kolab_gid'}, $oldcfg);
    #umask $oldmask;
    #delete $templates{$keytemplate};

    my $transport;
    if (!($transport = IO::File->new($cfg, 'a'))) {
        Kolab::log('T', "Unable to create Postfix $map map: $!", KOLAB_ERROR);
        exit(1);
    }

    my $ldap = Kolab::LDAP::create(
        $Kolab::config{'ldap_ip'},
        $Kolab::config{'ldap_port'},
        $Kolab::config{'bind_dn'},
        $Kolab::config{'bind_pw'}
	);

    my $mesg = $ldap->search(
        base    => 'k=kolab,'.$Kolab::config{'base_dn'},
        scope   => 'base',
        filter  => '(objectclass=*)'
	);
    if ($mesg->code) {
        Kolab::log('T', "Unable to locate Postfix $map map entries in LDAP", KOLAB_ERROR);
        exit(1);
    }

    my $ldapobject;
    if ($mesg->code <= 0) {
        foreach $ldapobject ($mesg->entries) {
            my $routes = $ldapobject->get_value("postfix-$map", asref => 1);
            foreach (@$routes) {
                $_ = trim($_);
                Kolab::log('T', "Adding entry `$_' to $map");
                print $transport $_ . "\n";
            }
        }
    } else {
        Kolab::log('T', "No Postfix $map map entries found");
    }

    Kolab::LDAP::destroy($ldap);
    $transport->close;

    # FIXME: bad way of doing things...
    #system("chown root:root @emailserver_confdir@/*");
    fixup( $cfg, $ownership{$cfg}, $permissions{$cfg});
    system("$Kolab::config{'postmapping'}/$map");

    if (-f $oldcfg) {
        my $rc = `diff -q $cfg $oldcfg`;
        chomp($rc);
        if ($rc) {
	    Kolab::log('T', "`$cfg' change detected: $rc", KOLAB_DEBUG);
	    $haschanged{'postfix'} = 1;
        }
    } else {
        $haschanged{'postfix'} = 1;
    }

    Kolab::log('T', 'Finished building Postfix $map map', KOLAB_DEBUG);
}

sub buildCyrusGroups
{
    Kolab::log('T', 'Building Cyrus groups', KOLAB_DEBUG);

    my $templatedir = $Kolab::config{"templatedir"};

    my $keytemplate = "$templatedir/imapd.group.template";
    my $cfg = $templates{$keytemplate};
    my $oldcfg = $cfg . '.old';
    #delete $templates{$keytemplate};

    #my $oldmask = umask 077;
    #copy($cfg, $oldcfg);
    #chown($Kolab::config{'kolab_uid'}, $Kolab::config{'kolab_gid'}, $oldcfg);
    #umask $oldmask;

    my $groupconf;
    if (!($groupconf = IO::File->new($cfg, 'a'))) {
        Kolab::log('T', "Unable to open configuration file `$cfg': $!", KOLAB_ERROR);
        exit(1);
    }

    my $ldap = Kolab::LDAP::create(
        $Kolab::config{'ldap_ip'},
        $Kolab::config{'ldap_port'},
        $Kolab::config{'bind_dn'},
        $Kolab::config{'bind_pw'}
	);

    my $mesg = $ldap->search(
        base    => $Kolab::config{'base_dn'},
        scope   => 'sub',
        filter  => '(&(mail=*)(objectclass=kolabgroupofnames))'
	);
    if ($mesg->code) {
        Kolab::log('T', 'Unable to locate Cyrus groups in LDAP', KOLAB_ERROR);
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
            print $groupconf $group . "\n";
            Kolab::log('T', "Adding cyrus group `$group'");
            $count++;
        }
    } else {
        Kolab::log('T', 'No Cyrus groups found');
    }

    $groupconf->close;
    Kolab::LDAP::destroy($ldap);

    fixup( $cfg, $ownership{$cfg}, $permissions{$cfg});

    Kolab::log('T', 'Finished building Cyrus groups', KOLAB_DEBUG );
}

sub buildLDAPAccess
{
    Kolab::log('T', 'Building LDAP access file', KOLAB_DEBUG);

    my $templatedir = $Kolab::config{"templatedir"};

    my $keytemplate = "$templatedir/slapd.access.template";
    if( ! -f $keytemplate ) {
        Kolab::log('T', "No LDAP access file `$keytemplate', skipping", KOLAB_DEBUG);
        return;
    }
    my $cfg = $templates{$keytemplate};
    my $oldcfg = $cfg . '.old';

    my $access;
    if (!($access = IO::File->new($cfg, 'a'))) {
        Kolab::log('T', "Unable to open configuration file `$cfg': $!", KOLAB_ERROR);
        exit(1);
    }

my $global_acl = <<'EOS';
# Domain specific access
access to filter=(&(objectClass=kolabInetOrgPerson)(mail=*@@@@domain@@@)(|(!(alias=*))(alias=*@@@@domain@@@)))
        by group/kolabGroupOfNames="cn=@@@domain@@@,cn=domains,cn=internal,@@@base_dn@@@" write
        by * break

access to filter=(&(objectClass=kolabGroupOfNames)(mail=*@@@@domain@@@))
        by group/kolabGroupOfNames="cn=@@@domain@@@,cn=domains,cn=internal,@@@base_dn@@@" write
        by * break

access to filter=(&(objectClass=kolabSharedFolder)(cn=*@@@@domain@@@))
        by group/kolabGroupOfNames="cn=@@@domain@@@,cn=domains,cn=internal,@@@base_dn@@@" write
        by * break

EOS

my $dom_acl1 = << 'EOS';
# Access to domain groups
access to dn.children="cn=domains,cn=internal,@@@base_dn@@@"
        by group/kolabGroupOfNames="cn=admin,cn=internal,@@@base_dn@@@" write
        by group/kolabGroupOfNames="cn=maintainer,cn=internal,@@@base_dn@@@" write
        by dn="cn=nobody,cn=internal,@@@base_dn@@@" read
EOS

my $dom_acl2 = << 'EOS';
        by group/kolabGroupOfNames="cn=@@@domain@@@,cn=domains,cn=internal,@@@base_dn@@@" read
EOS

my $dom_acl3 = << 'EOS';
         by * search stop
EOS

	my $str;
    my $domain;
    my @domains;
    if( ref($Kolab::config{'postfix-mydestination'}) eq 'ARRAY' ) {
	@domains = @{$Kolab::config{'postfix-mydestination'}};
    } else {
	@domains =( $Kolab::config{'postfix-mydestination'} );
    }

    ($str = $dom_acl1) =~ s/\@{3}base_dn\@{3}/$Kolab::config{'base_dn'}/g;
    print $access $str;

    foreach $domain (@domains) {
	($str = $dom_acl2) =~ s/\@{3}domain\@{3}/$domain/g;
	$str =~ s/\@{3}base_dn\@{3}/$Kolab::config{'base_dn'}/g;	
	print $access $str;
    }

    ($str = $dom_acl3) =~ s/\@{3}base_dn\@{3}/$Kolab::config{'base_dn'}/g;
    print $access $str;

    foreach $domain (@domains) {
	($str = $global_acl) =~ s/\@{3}domain\@{3}/$domain/g;
	$str =~ s/\@{3}base_dn\@{3}/$Kolab::config{'base_dn'}/g;	
	print $access $str;
	Kolab::log('T', "Adding acl for domain '$str'");
    }

    $access->close;

    if (-f $oldcfg) {
        my $rc = `diff -q $cfg $oldcfg`;
        chomp($rc);
        if ($rc) {
	    Kolab::log('T', "`$cfg' change detected: $rc", KOLAB_DEBUG);
	    $haschanged{'slapd'} = 1;
        }
    } else {
        $haschanged{'slapd'} = 1;
    }

    fixup( $cfg, $ownership{$cfg}, $permissions{$cfg});

    Kolab::log('T', 'Finished building LDAP access file', KOLAB_DEBUG );
}

sub buildLDAPReplicas
{
    Kolab::log('T', 'Building LDAP replicas', KOLAB_DEBUG);

    my $templatedir = $Kolab::config{"templatedir"};

    my $keytemplate = "$templatedir/slapd.replicas.template";
    if( ! -f $keytemplate ) {
        Kolab::log('T', "No LDAP replicas `$keytemplate', skipping", KOLAB_DEBUG);
        return;
    }
    my $cfg = $templates{$keytemplate};
    my $oldcfg = $cfg . '.old';

    my $repl;
    if (!($repl = IO::File->new($cfg, 'a'))) {
        Kolab::log('T', "Unable to open configuration file `$cfg': $!", KOLAB_ERROR);
        exit(1);
    }

    # directory_mode syncrepl is supported from openldap-2.3.x and beyond
    if ($Kolab::config{'directory_mode'} eq "syncrepl") {

      if ( $Kolab::config{'is_master'} eq "false" ) {
        # Output a syncrepl statement for database synchronisation
        print $repl "syncrepl rid=0 \n"
                 ."         provider=".$Kolab::config{"ldap_master_uri"}."\n"
                 ."         type=refreshAndPersist\n"
                 ."         retry=\"60 10 300 +\"\n"
                 ."         searchbase=\"".$Kolab::config{'base_dn'}."\"\n"
                 ."         scope=sub\n"
                 ."         schemachecking=on\n"
                 ."         binddn=\"".$Kolab::config{"bind_dn"}."\"\n"
                 ."         credentials=\"".$Kolab::config{"bind_pw"}."\"\n"
                 ."         bindmethod=simple\n";
      }

    } else {

      if( $Kolab::config{'is_master'} eq "true" ) {
  	# Master setup
  	my @kh;
  	if( ref $Kolab::config{'kolabhost'} eq 'ARRAY' ) {
  	    @kh = @{$Kolab::config{'kolabhost'}};
  	} else {
  	    @kh = ( $Kolab::config{'kolabhost'} );
  	}
  	for my $h ( @kh ) {
  	    next if lc($h) eq lc($Kolab::config{'fqdnhostname'});
  	    print $repl "replica uri=ldaps://$h\n"
  		."  binddn=\"".$Kolab::config{'bind_dn'}."\"\n"
  		."  bindmethod=simple credentials=".$Kolab::config{'bind_pw'}."\n\n";
  	}
      } else {
  	# Slave setup
  	# Output an update dn statement instead
  	print $repl "updatedn ".$Kolab::config{'bind_dn'}."\n";
  	print $repl "updateref ".$Kolab::config{'ldap_master_uri'}."\n";
      }
    }

    $repl->close;

    fixup( $cfg, $ownership{$cfg}, $permissions{$cfg});

    if (-f $oldcfg) {
        my $rc = `diff -q $cfg $oldcfg`;
        chomp($rc);
        if ($rc) {
	    Kolab::log('T', "`$cfg' change detected: $rc", KOLAB_DEBUG);
	    $haschanged{'slapd'} = 1;
        }
    } else {
        $haschanged{'slapd'} = 1;
    }

    Kolab::log('T', 'Finished building LDAP replicas', KOLAB_DEBUG);
}

sub replaceMetaVar
{	
    my $var = shift;

    while ($var =~ /\@{3}([^\s\@]+?)\@{3}/) {
	my $attr = $1;
	if ($Kolab::config{$attr}) {
	    my $val = $Kolab::config{$attr};
	    $var =~ s/\@{3}([^\s\@]+?)\@{3}/$val/;
	} else {
	    Kolab::log('T', "No configuration variable corresponding to `$1' exists", KOLAB_WARN);
	}
    }
    return $var;
}


sub loadMetaTemplates
{	
    my $templatedir = shift;
    my ($tref, $pref, $oref, $cmdref, $ccharref) = @_;

    Kolab::log('T', 'Collecting template files', KOLAB_DEBUG );
    opendir(DIR, $templatedir) or Kolab::log('T', 'Given templatedir $templatedir does not exist!', KOLAB_ERROR );
    my @metatemplates = grep { /\.template$/ } readdir (DIR);
    closedir(DIR);

    foreach my $template (@metatemplates) {
	my $runonchange = undef;
	my $commentchar = undef;
	#Open each file and check for the META
	if (open (TEMPLATE, "$templatedir/$template" )) {
	    my $line = <TEMPLATE>;
	    if ($line =~ /^KOLAB_META_START$/) {
		Kolab::log('T', 'Processing META template :'.$template, KOLAB_DEBUG );
		my ($found_end, $target, $permissions, $ownership);
		while (<TEMPLATE>) {
		    $line = $_;
		    
		    if (!$found_end) {
			$found_end = $line =~ /^KOLAB_META_END$/;
			if (!$found_end && $line) {
			    my ($key,$value) = split(/=/,$line);
			    chomp($value);
			    Kolab::log('T', 'META Key: '.$key.' Value: '.$value, KOLAB_DEBUG );
			    if ($key =~ /^TARGET$/) {
				$target = replaceMetaVar($value);
				Kolab::log('T', 'META Target '.$target, KOLAB_DEBUG );
			    } elsif ($key =~ /^PERMISSIONS$/) {
				$permissions = replaceMetaVar($value);
				Kolab::log('T', 'META Permissions '.$permissions, KOLAB_DEBUG );
			    } elsif ($key =~ /^OWNERSHIP$/) {
				$ownership = replaceMetaVar($value);
				Kolab::log('T', 'META Ownership '.$ownership, KOLAB_DEBUG );
			    } elsif ($key =~ /^RUNONCHANGE$/) {
				$runonchange = replaceMetaVar($value);
				Kolab::log('T', 'META Cmd to execute '.$runonchange, KOLAB_DEBUG );
			    } elsif ($key =~ /^COMMENT_CHAR$/) {
			      $commentchar = replaceMetaVar($value);
			      Kolab::log('T', 'META CommentChar to use: '.$commentchar, KOLAB_DEBUG );
			    } else {
			        Kolab::log('T', 'incorrect META key "'.$key.'" in: '.$template, KOLAB_WARN );
			    }
			}
		    }
		}
		if ($found_end && $target && $permissions && $ownership) {
		    Kolab::log('T', 'All mandatory fields populated in '.$template, KOLAB_DEBUG );
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
	    Kolab::log('T', 'Could not open template file: '. $template, KOLAB_WARN);
	}
    }

}

sub rebuildTemplates
{
    my $key;
    my $value;
    my $section="";
    my %runonchange;

    my $templatedir = $Kolab::config{"templatedir"};

    Kolab::log('T', 'Regenerating configuration files', KOLAB_DEBUG );

    Kolab::log('T', 'Loading meta-template data', KOLAB_DEBUG );
    loadMetaTemplates( $templatedir, \%templates, \%permissions, \%ownership, \%runonchange, \%commentchar );

    my $cfg;
    my $tpl;
    foreach $tpl (keys %templates) {
        $cfg = $templates{$tpl};
        #print STDOUT "Rebuilding $tpl => $cfg\n";
        build($tpl, $cfg, $ownership{$cfg}, $permissions{$cfg}, $commentchar{$cfg});
     }

    buildPostfixTransportMap;
    buildPostfixVirtualMap;
    buildLDAPAccess;
    buildLDAPReplicas;
    buildCyrusGroups;

    Kolab::log('T', 'Finished regenerating configuration files', KOLAB_DEBUG );

    foreach $key (keys %runonchange) {
	if (defined $templatehaschanged{$key})
	{
	    Kolab::log('T', 'Actioning RUNONCHANGE for '.$key, KOLAB_DEBUG );
	    my $cmd = $runonchange{$key};
	    system($cmd);
	    Kolab::log('T', 'Executing command', KOLAB_DEBUG );
	}
    }
}

sub bootstrapConfig
{
    my $templatedir = $Kolab::config{"templatedir"};

    # FIXME: it would be better if the templates can be given as an
    # argument to this function.
    my @templ = ("$templatedir/slapd.access.template",
      "$templatedir/slapd.conf.template",
      "$templatedir/slapd.replicas.template");
 
    my %runonchange;

    loadMetaTemplates( $templatedir, \%templates, \%permissions, \%ownership, \%runonchange, \%commentchar );

    my $cfg;
    my $out;
    foreach my $tpl (@templ) {
      $cfg = $templates{$tpl};
      # print STDOUT "Rebuilding $tpl => $cfg\n";
      build($tpl, $cfg, $ownership{$cfg}, $permissions{$cfg}, $commentchar{$cfg});
    }
}

sub checkPermissions {
    my $key;
    my $value;

    my $templatedir = $Kolab::config{"templatedir"};

    Kolab::log('T', 'Checking generated config file permissions and ownership', KOLAB_DEBUG );

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
		Kolab::log('T', $str, KOLAB_ERROR );
		$ok = 0;
	    }
	} else {
	    my $str = "File $tpl does not exist";
	    print "$str\n";
	    Kolab::log('T', "$str", KOLAB_ERROR );
	}
    }
    return $ok;
}

sub reload
{
    if ($haschanged{'slapd'}) {
        &Kolab::log('K', 'Restarting OpenLDAP...');
        system("$Kolab::config{'KOLABRC'} rc openldap restart &");
    }

    if ($haschanged{'saslauthd'}) {
        &Kolab::log('K', 'Restarting SASLAuthd...');
        system("$Kolab::config{'KOLABRC'} rc sasl stop; sleep 1; $Kolab::config{sbindir}/saslauthd -a ldap -n 5");
    }

    if ($haschanged{'apache'}) {
        &Kolab::log('K', 'Reloading Apache...');
        system("$Kolab::config{sbindir}/apachectl graceful");
    }

    if ($haschanged{'postfix'}) {
        &Kolab::log('K', 'Reloading Postfix...');
        system("$Kolab::config{sbindir}/postfix reload");
    }

    if ($haschanged{'imapd'}) {
        &Kolab::log('K', 'Restarting imapd...');
	# Would it be enough with a reload here? /steffen
        system("$Kolab::config{'KOLABRC'} rc imapd restart");
    }

    if ($haschanged{'amavisd'}) {
        &Kolab::log('K', 'Restarting amavisd...');
        system("$Kolab::config{'KOLABRC'} rc amavisd restart");
    }

    if ($haschanged{'clamav'}) {
        &Kolab::log('K', 'Restarting clamav...');
        system("$Kolab::config{'KOLABRC'} rc clamav restart");
    }

    %Kolab::Conf::haschanged = ();

    &Kolab::log('K', 'Reload finished');
}

1;
__END__
=head1 NAME

Kolab::Conf - Perl extension for Kolab template generation

=head1 ABSTRACT

  Kolab::Conf handles the generation of template files, used by
  kolabconf.

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
