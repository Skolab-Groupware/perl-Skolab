package Kolab::LDAP;

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
use UNIVERSAL;
use Time::Local;
use Net::Domain qw(hostfqdn);
use Net::LDAP qw( LDAP_SUCCESS LDAP_PROTOCOL_ERROR LDAP_REFERRAL );
use Net::LDAPS;
use Net::LDAP::Util;
use DB_File;
use Kolab;
use Kolab::Util;
use Kolab::Cyrus;
use Digest::SHA qw(sha1);
use MIME::Base64 qw(encode_base64);

require Exporter;

our @ISA = qw(Exporter);

our %EXPORT_TAGS = (
    'all' => [ qw(
        &startup
        &shutdown
        &create
        &destroy
        &ensureAsync
        &isObject
        &isDeleted
        &createObject
        &deleteObject
        &sync
    ) ]
);

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(

);

our $VERSION = '0.9';

# Timestamp to keep track of changed objects
our $user_timestamp = "";
our $sf_timestamp = "";
our $group_timestamp = "";
our $db_statedir = '';
our %newuid_db;

sub startup
{
    my $statedir = shift || '';

    Kolab::log('L', 'Starting up');

    if (!$db_statedir && $statedir) {
	$db_statedir = $statedir;
    }

}

sub shutdown
{
    Kolab::log('L', 'Shutting down');
}

sub uidcacheOpen
{
    Kolab::log('L', 'Opening mailbox uid cache DB');

    my %uid_db;
    if (!dbmopen(%uid_db, $Kolab::config{'kolab_mailboxuiddb'}, 0666)) {
        Kolab::log('L', 'Unable to open mailbox uid cache DB', KOLAB_ERROR);
        exit(1);
    }

    return \%uid_db;
}

sub uidcacheClose (\%)
{
    my ($uid_db) = @_;
    dbmclose(%{$uid_db});
    untie %{$uid_db};
}

sub uidcacheStore
{
    my $guid = shift;
    my $uid = shift;

    my $uid_db = uidcacheOpen();

    ${$uid_db}{$guid} = $uid;

    uidcacheClose(%$uid_db);
}

sub uidcacheFetch
{
    my $guid = shift;

    my $uid_db = uidcacheOpen();

    my $uid = ${$uid_db}{$guid} || '';

    uidcacheClose(%$uid_db);

    return $uid;
}

sub uidcacheDelete
{
    my $guid = shift;

    my $uid_db = uidcacheOpen();

    delete ${$uid_db}{$guid};

    uidcacheClose(%$uid_db);
}

sub graveyardOpen
{
    Kolab::log('L', 'Opening graveyard uid/timestamp cache DB');

    my %gyard_db;
    if (!dbmopen(%gyard_db, $Kolab::config{'graveyard_uidcache'}, 0666)) {
        Kolab::log('L', 'Unable to open graveyard uid cache DB', KOLAB_ERROR);
        exit(1);
    }

    my %gyard_ts_db;
    if (!dbmopen(%gyard_ts_db, $Kolab::config{'graveyard_tscache'}, 0666)) {
        Kolab::log('L', 'Unable to open graveyard timestamp cache DB', KOLAB_ERROR);
        exit(1);
    }
    return \(%gyard_db, %gyard_ts_db);
}

sub graveyardClose (\%\%)
{
    my ($gyard_db, $gyard_ts_db) = @_;

    dbmclose(%$gyard_db);
    dbmclose(%$gyard_ts_db);

    untie %$gyard_db;
    untie %$gyard_ts_db;
}

sub graveyardRessurect
{
    my $guid = shift;
    my $uid = shift;

    my $gyard_db;
    my $gyard_ts_db;
    ($gyard_db, $gyard_ts_db) = graveyardOpen();

    my $oldgyarduid = $$gyard_db{$guid} || '';
    if ($oldgyarduid) {
	# The object needs to be resurrected!
	if ($oldgyarduid ne $uid) {
	    Kolab::log('L', "Resurrected object `$uid' already exists as `$oldgyarduid'; refusing to create", KOLAB_WARN);
	} else {
	    Kolab::log('L', "Object `$uid' has been resurrected", KOLAB_DEBUG);
	}
	# Remove the object from the graveyard
	delete $$gyard_db{$guid};
	delete $$gyard_ts_db{$guid};
    }

    graveyardClose(%$gyard_db, %$gyard_ts_db);

    return $oldgyarduid;
}

sub graveyardStore
{
    my $guid = shift;
    my $uid = shift;

    my $gyard_db;
    my $gyard_ts_db;
    ($gyard_db, $gyard_ts_db) = graveyardOpen();

    $$gyard_db{$guid} = $uid;
    $$gyard_ts_db{$guid} = time;

    graveyardClose(%$gyard_db, %$gyard_ts_db);
}

sub graveyardCleanup
{
    my $guid = shift;
    my $uid = shift;

    my $gyard_db;
    my $gyard_ts_db;
    ($gyard_db, $gyard_ts_db) = graveyardOpen();

    my $now = time;
    my $period = $Kolab::config{'gyard_deletion_period'} * 60;
    Kolab::log('L', 'Gravekeeping (period = ' . $Kolab::config{'gyard_deletion_period'} . ' minutes)');
    foreach $guid (keys %$gyard_ts_db) {
        if ($now - $$gyard_ts_db{$guid} > $period) {
            Kolab::log('L', "Clearing graveyard database entry `" . $$gyard_db{$guid} . "'");
            #Kolab::Cyrus::deleteMailbox($cyrus, $$gyard_db{$guid}, 0);
            delete $$gyard_ts_db{$guid};
            delete $$gyard_db{$guid};
        }
    }

    graveyardClose(%$gyard_db, %$gyard_ts_db);
}

sub quotaOpen
{
    Kolab::log('L', 'Opening mailbox quota cache DB');

    my %quota_db;
    if (!dbmopen(%quota_db, "$db_statedir/mailbox-quotacache.db", 0666)) {
        Kolab::log('L', 'Unable to open mailbox quota cache DB', KOLAB_ERROR);
        exit(1);
    }

    return \%quota_db;
}

sub quotaClose (\%)
{
    my ($quota_db) = @_;

    dbmclose(%$quota_db);
    untie $quota_db;
}

sub quotaStore
{
    my $guid = shift;
    my $quota = shift;

    my $quota_db = quotaOpen();

    $$quota_db{$guid} = $quota;

    quotaClose(%$quota_db);
}

sub quotaFetch
{
    my $guid = shift;

    my $quota_db = quotaOpen();

    my $quota = $$quota_db{$guid} || 0;

    quotaClose(%$quota_db);

    return $quota;
}

sub quotaDelete
{
    my $guid = shift;

    my $quota_db = quotaOpen();

    delete $$quota_db{$guid};

    quotaClose(%$quota_db);
}



sub create
{
    my $ip = shift;
    my $pt = shift;
    my $dn = shift;
    my $pw = shift;
    my $as = shift || 0;

    Kolab::log('L', "Connecting to LDAP server `$ip:$pt'");

    my $ldap;
    if( $pt == 636 ) {
      # Use SSL
      $ldap = Net::LDAPS->new(
        $ip,
        port    => $pt,
        version => 3,
        timeout => 20,
        async   => $as,
	verify => 'none',
	onerror => \&ldap_error
      );
    } else {
      $ldap = Net::LDAP->new(
        $ip,
        port    => $pt,
        version => 3,
        timeout => 20,
        async   => $as,
	onerror => \&ldap_error
      );
    }
    if (!$ldap) {
        Kolab::log('L', "Unable to connect to LDAP server `$ip:$pt'", KOLAB_ERROR);
        if ($as) { return 0; } else { exit(1); }
    }

    Kolab::log('L', "Binding to `$dn'");
    my $ldapmesg = $ldap->bind(
        $dn,
        password    => $pw
    );
    if ($ldapmesg->code) {
        Kolab::log('L', "Unable to bind to `$dn', LDAP Error = `" . $ldapmesg->error . "'", KOLAB_ERROR);
        if ($as) { return 0; } else { exit(1); }
    }

    return $ldap;
}

sub destroy
{
    my $ldap = shift;

    if (defined($ldap) && ($ldap->isa('Net::LDAP') || $ldap->isa('Net::LDAPS'))) {
        $ldap->unbind;
        $ldap->disconnect;
    }
}

sub ensureAsync
{
    my $ldap = shift || 0;

    if ($ldap && !$ldap->async) {
        Kolab::log('L', 'LDAP operations are not asynchronous', KOLAB_ERROR);
        exit(1);
    }

    Kolab::log('L', 'LDAP operations are asynchronous', KOLAB_DEBUG);
}

sub isObject
{
    my $object = shift;
    my $class = shift;

    my $classes = $object->get_value('objectClass', asref => 1);
    return 0 if !defined($classes);
    foreach my $oc (@$classes) {
        if ($oc =~ /$class/i) {
            return 1;
        }
    }
    return 0;
}

sub isDeleted
{
    my $object = shift;
    my $p = shift || 'user';
    my $del = $object->get_value($Kolab::config{$p . '_field_deleted'}, asref => 1 );
    #foreach (@$del) {
    #  return 1 if lc($_) eq lc($Kolab::config{'fqdnhostname'});
    #}
    #return 0;
    return $#$del > 0;
}

# Map from Kolab ACLs to Cyrus ACLs
sub mapAcls {
  my $acls = shift;
  my $sf = shift || 0;
  my @acls = map {
    my ($uid,$perm) = split(/\s+/,$_,2);
    Kolab::log('L', "Kolab::LDAP::mapAcls() uid=$uid perm=$perm", KOLAB_DEBUG);
    my $post = 0;
    if( $perm =~ /(.*)\/post/ ) {
      $perm = $1;
      $post = 1;
    }
    Kolab::log('L', "Kolab::LDAP::mapAcls() uid=$uid perm=$perm post=$post", KOLAB_DEBUG);
    if( lc $perm eq 'none' ) { $_ = "$uid none"; }
    elsif( lc $perm eq 'post' ) { $_ = "$uid p"; }
    elsif( lc $perm eq 'read' ) { $_ = "$uid lrs"; }
    elsif( lc $perm eq 'read anon' ) { $_ = "$uid lr"; }
    elsif( lc $perm eq 'read hidden' ) { $_ = "$uid rs"; }
    elsif( lc $perm eq 'append' ) { $_ = "$uid lrsip"; }
    elsif( lc $perm eq 'write' ) { if( $sf ) { $_ = "$uid lrsiwdp"; } else { $_ = "$uid lrsiwcdp"; } }
    elsif( lc $perm eq 'all' ) { if( $sf ) { $_ = "$uid lrsiwdap"; } else { $_ = "$uid lrsiwcdap"; } }
    else { $_ = "$uid $perm"; } # passthrough
    if( $post ) { $_ .= 'p'; }
    Kolab::log('L', "Kolab::LDAP::mapAcls() acl=$_", KOLAB_DEBUG);
  } @$acls;
  if( $sf ) {
    push(@$acls, "manager lrsiwcdap");
  }
  Kolab::log('L', "Kolab::LDAP::mapAcls() acls=".join(", ", @$acls), KOLAB_DEBUG);
  return $acls;
}

sub createObject
{
    my $ldap = shift;
    my $cyrus = shift;
    my $object = shift;
    my $sync = shift || 0;
    my $p = shift || 'user';
    my $doacls = shift || 0;
    my $objuidfield = shift || ($p eq 'user' ? 'mail' : ($p eq 'sf' ? 'cn' : ''));

    Kolab::log('L', "Kolab::LDAP::createObject() called with obj uid field `$objuidfield' for obj type `$p'", KOLAB_DEBUG);

    # No action for groups or external
    return if( $objuidfield eq '' );
    my $uid = lc(trim($object->get_value($objuidfield))) || 0;
    return unless $uid;
    return if( $objuidfield eq 'mail' && !$object->get_value('uid') );

    my $kolabhomeserver = lc($object->get_value('kolabhomeserver'));
    my $kolabimapserver = lc($object->get_value('kolabimapserver'));
    my $islocal = 1;
    my $del = $object->get_value($Kolab::config{$p . '_field_deleted'}, asref => 1);
    if( ref($del) eq 'ARRAY' && @$del > 0 ) {
        Kolab::log('L', "Kolab::LDAP::createObject() skipping object ".lc($object->get_value($objuidfield))
            ." because it is deleted", KOLAB_DEBUG);
        return;
    }
    if( ($kolabhomeserver && $kolabhomeserver ne lc($Kolab::config{'fqdnhostname'})) 
        || $kolabimapserver && $kolabimapserver ne lc(hostfqdn()) ) {
        # We are not on the home server
        if( $p eq 'sf' ) {
            # Dont create shared folders on other hosts than it's kolabhomeserver
            Kolab::log('L', "Kolab::LDAP::createObject() skipping shared folder for other server $kolabhomeserver", KOLAB_DEBUG);
            return;
        }
        my $kolabhomeserveronly = $object->get_value('kolabhomeserveronly');
        if( defined($kolabhomeserveronly) && $kolabhomeserveronly eq 'true' ) {
            # Don't create the user's mailbox if it should be created on the kolabHomeServer only
            Kolab::log('L', "Kolab::LDAP::createObject() skipping user mailbox creation for other server $kolabhomeserver", KOLAB_DEBUG);
            return;
        }
        Kolab::log('L', "Kolab::LDAP::createObject() for other server than $kolabhomeserver. TODO: Create referral or something, for now we just create an empty INBOX", KOLAB_DEBUG);
        # We create INBOX on other servers also, to allow access to shared/published
        # folders on those servers because some IMAP clients abort the connection
        # to an IMAP server if they cannot access the INBOX.
        $islocal = 0;
    }

    if (!$cyrus) {
        Kolab::log('L', 'object wants mailbox, but not connected to imap, returning', KOLAB_DEBUG);
        return;
    }

    # Intermediate multidomain support:
    # We accept domain encoded in CN...
    if( $p eq 'sf' && index( $uid, '@' ) < 0 ) {
        # We have to create shared folders
        # with names shared.<fldrname>@<domain>
        my @dcs = split(/,/,$object->dn());
        my @dn;
        while( pop( @dcs ) =~ /dc=(.*)/ ) {
            push(@dn, $1);
        }
        if( $#dn > 0 ) { $uid .= '@'.join('.',reverse(@dn)); }
    }
    if (!$uid) {
        Kolab::log('L', "Kolab::LDAP::createObject() called with null id attribute `$objuidfield', returning", KOLAB_DEBUG);
        return;
    }

    Kolab::log('L', "Synchronising object `$uid'", KOLAB_DEBUG);

    my $guid = $object->get_value($Kolab::config{$p . '_field_guid'});
    Kolab::log('L', "GUID attribute `" . $Kolab::config{$p . '_field_guid'} . "' is `$guid'", KOLAB_DEBUG);
    my $olduid = uidcacheFetch($guid);
    if ($olduid) {
        # We have records of the object
        $newuid_db{$guid} = $olduid if ($sync);
        if ($olduid ne $uid) {
            # The mailbox changed; bitch
            Kolab::log('L', "Object `$uid' already exists as `$olduid'; refusing to create", KOLAB_WARN);
        } else {
            Kolab::log('L', "Object `$uid' already exists, skipping", KOLAB_DEBUG);
        }
        # Nothing changed; nothing to do
    } else {
        # No official records - check the graveyard
        my $oldgyarduid = graveyardRessurect($guid, $uid);
        if ($oldgyarduid) {
            if ($sync) { $newuid_db{$guid} = $oldgyarduid; } else { uidcacheStore($guid, $oldgyarduid); }
        } else {
            Kolab::log('L', "Creating user `$uid' corresponding to GUID `$guid'", KOLAB_DEBUG);
            my $partition = '';
            my $imappartitions_script = $Kolab::config{'imappartitions_script'};
            if ($imappartitions_script) {
                my @partitions;
                if (@partitions = `$imappartitions_script`) {
                    $partition = $partitions[rand($#partitions + 1)];
                    chomp $partition;
                } else {
                    Kolab::log('L', "Unable to run imappartitions_script `$imappartitions_script': $!", KOLAB_ERROR);
                }
            }
            # We have a object that we have no previous record of, so create everything
            if ($sync) { $newuid_db{$guid} = $uid; } else { uidcacheStore($guid, $uid); }
            Kolab::Cyrus::createMailbox($cyrus, $uid, ($p eq 'sf' ? 1 : 0), $partition);
            if( $p eq 'sf' ){
                my $foldertype = lc($object->get_value('kolabfoldertype'));

                if ( $foldertype ne '' ){
                    Kolab::Cyrus::setFolderType($cyrus,$uid,1,$foldertype);
                }
            }
            if( $p ne 'sf' && !$islocal ) {
                # Hide user mailboxes on other servers
                Kolab::Cyrus::setACL($cyrus,$uid,0, ["$uid rs"]);
            } elsif( $p ne 'sf' ) {
                # Deal with group and resource accounts
                my $edn = Net::LDAP::Util::ldap_explode_dn($object->dn(), casefold=>'lower' );
                my $gcn = $edn->[1]->{'cn'};
                if( $gcn && ($gcn eq 'groups' || $gcn eq 'resources') ) {
                    # We need to give the calendar user access to the
                    # group's/resource's Calendar folder.
                    # TODO: Don't hardcode user and folder name
                    Kolab::log('L', "Detected group or resource account, creating calendar folder", KOLAB_DEBUG );
                    my $domain;
                    my $user;
                    if ($uid =~ /(.*)\@(.*)/) {
                        $user = $1;
                        $domain = $2;
                    } else {
                        $user = $uid;
                        $domain = $Kolab::config{'postfix-mydomain'};
                    }
                    my $folder = $user . '/Calendar@' . $domain;
                    Kolab::Cyrus::createCalendar($cyrus, $user, $domain, $folder, ["$uid all", 'calendar@' . $domain .' all']);
                }
            }
        }
    }

    if ($doacls) {
        my $acls = $object->get_value('acl', 'asref' => 1);
        Kolab::Cyrus::setACL($cyrus, $uid, ($p eq 'sf' ? 1 : 0), mapAcls( $acls, ($p eq 'sf' ? 1:0)));
    }

    my $quota = $object->get_value($Kolab::config{$p . '_field_quota'});
    defined($quota) or ($quota = 0);
    my $oldquota = quotaFetch($guid);
    if( $quota != $oldquota ) {
        Kolab::Cyrus::setQuota($cyrus, $uid, $quota*1024, ($p eq 'sf' ? 1 : 0));
        if( $quota == 0 ) {
            quotaDelete($guid);
        } else {
            quotaStore($guid, $quota);
        }
    }
    Kolab::log('L', "createObject() done", KOLAB_DEBUG );
}

sub createMasterLDAP {
  my $uri = $Kolab::config{'ldap_master_uri'};

  my $masterldap = Net::LDAP->new(
	 $uri,
	 version => 3,
	 timeout => 20,
	 verify => 'none',
	 onerror => 'undef' );
  if( defined( $masterldap ) ) {
    my $mesg = $masterldap->bind(
				 $Kolab::config{'bind_dn'},
				 password    => $Kolab::config{'bind_pw'});
    if ($mesg->code) {
      Kolab::log('L', "Unable to bind to `$uri', LDAP Error = `"
		 .$mesg->error."'", KOLAB_ERROR);
      undef( $masterldap );
    }
  } else {
    Kolab::log('L', "Unable to connect to `$uri'"
	       , KOLAB_ERROR);
  }
  return $masterldap;
}

sub deleteObject
{
    # This should only ever be called if the object is specifically flagged for
    # deletion, as we nuke the mailbox
    #
    # The graveyard code will handle the case of an object `going missing'.
    
    my $ldap = shift;
    my $cyrus = shift;
    my $object = shift;
    my $remfromldap = shift || 0;
    my $p = shift || 'user';

    my $guid = $object->get_value($Kolab::config{$p . '_field_guid'});
    my $uid = uidcacheFetch($guid);
    if ($uid && !$cyrus) {
        Kolab::log('L', 'object found in mboxcache, but not connected to imap, returning', KOLAB_DEBUG);
        return;
    }

    if ($remfromldap) {
        my $dn = $object->dn;
	my $del = $object->get_value($Kolab::config{$p . '_field_deleted'}, asref => 1);
	my $masterldap;
	if( $Kolab::config{'ldap_master_uri'} eq $Kolab::config{'ldap_uri'} ) {
	  # We are already connected to the LDAP master, just go ahead
	  $masterldap = $ldap;
	} else {
	  $masterldap = createMasterLDAP;
	}
	if( !defined( $masterldap ) ) {
	  # Problem here, could not connect to master!
	  Kolab::log('L', "Unable to remove DN `$dn', master LDAP server not available", KOLAB_WARN);
	  return 0;
	}
	if( lc ($Kolab::config{'is_master'}) eq 'true' && ref($del) eq 'ARRAY' && scalar(@$del) == 1 ) {
	    # Ok we are the last one and the master
	    if( $Kolab::config{'kolab_remove_objectclass'} ) {
		# Remove the kolab-related objectClasses
		# Some people find it useful to integrate Kolab 
		# with an existing LDAP database and when a Kolab
		# object is to be deleted, it should just remove
		# the Kolab stuff and leave the rest of the object
		# in the database.
		#
		# This is what we do here. 
		# Warning: All attributes in the kolab-related 
		# objectclasses will be deleted!
		#
		# PENDING(steffen): Only remove attributes that _have_ to
		# be removed.
		Kolab::log('L', "Removing Kolab objectClasses from DN `$dn'");
		my $schema = $masterldap->schema( $dn );
                # PENDING(steffen): Dont hardcode objectClasses
		foreach my $c qw(kolabInetOrgPerson kolabGroupOfNames) {
		    my @may = map $_->{name}, $schema->may($c);
		    my @must = map $_->{name}, $schema->must($c);
		    foreach my $attr (@must,@may,split(' ',$Kolab::config{'kolab_remove_attributes'})) {
			# Remove attributes
			Kolab::log('L', "Removing attribute $attr", KOLAB_WARN);
			my $mesg = $masterldap->modify( $dn,
							delete => $attr );
			if ($mesg && $mesg->code ) {
			    Kolab::log('L', "Unable to remove attribute $attr from DN `$dn': ".$mesg->error, KOLAB_WARN);
			}
		    }
		    # Remove objectClass
		    my $mesg = $masterldap->modify( $dn,
						    delete => { 'objectClass' => $c } );
		    if ($mesg && $mesg->code ) {
			Kolab::log('L', "Unable to remove Kolab objectClas $_ from DN `$dn': ".$mesg->error, KOLAB_WARN);
		    }
		}
	    } else {
		# Default behaviour, delete the object
		Kolab::log('L', "Removing DN `$dn'");
		my $mesg = $masterldap->delete($dn);
		if ($mesg && $mesg->code ) {
		    Kolab::log('L', "Unable to remove DN `$dn': ".$mesg->error, KOLAB_WARN);
		}
	    }
	} elsif( lc ($Kolab::config{'is_master'}) eq 'false' ) {
	  # Just remove us from the kolabdeleteflag
	  # master does not perform this step as it should 
	  # be the last to delete and remove the object
	  Kolab::log('L', "Removing ".$Kolab::config{'fqdnhostname'}." from ".
		     $Kolab::config{$p . '_field_deleted'}." in `$dn'");
	  my $mesg = $masterldap->modify( $dn, delete =>
					  { $Kolab::config{$p . '_field_deleted'} =>
					    $Kolab::config{'fqdnhostname'} } );
	  if ($mesg && $mesg->code) {
	    Kolab::log('L', "Unable to remove ".$Kolab::config{'fqdnhostname'}
		       ." from kolabdeleteflag in `$dn': ".$mesg->error, KOLAB_WARN);
	  }
	}
	if( $ldap != $masterldap ) {
	  # Disconnect from master if we are the slave
	  $masterldap->disconnect;
	}
    }

    my $hooksdir = $Kolab::config{'kolab_hooksdir'} . '/delete';
    opendir(DIR, $hooksdir) or Kolab::log('T', 'Given hook directory $hooksdir does not exist!', KOLAB_ERROR );
    my @hooks = grep { /^hook-/ } readdir (DIR);
    closedir(DIR);

    foreach my $hook (@hooks) {
	system($Kolab::config{'kolab_hooksdir'} . '/delete/' . $hook . " $uid");
	if ($?==0) {
	    Kolab::log('L', "Successfully ran hook $hook for user $uid.", KOLAB_DEBUG);
	} else {
	    Kolab::log('L', "Failed running hook $hook for user $uid.", KOLAB_ERROR);
	}
    }

    if (!$uid) {
        Kolab::log('L', 'Deleted object not found in mboxcache, returning', KOLAB_DEBUG);
        return;
    }

    Kolab::Cyrus::deleteMailbox($cyrus, $uid, ($p eq 'sf' ? 1 : 0));
    uidcacheDelete($guid);
    quotaDelete($guid);
    return 1;
}

sub sync
{
    Kolab::log('L', 'Synchronising');

    my $cyrus = Kolab::Cyrus::create;
    %newuid_db = ();

    $user_timestamp  = syncBasic($cyrus, 'user', '', $user_timestamp, 0);
    $sf_timestamp    = syncBasic($cyrus, 'sf', '', $sf_timestamp, 1);
    $group_timestamp = syncBasic($cyrus, 'group', '', $group_timestamp, 0);

    if( !$cyrus ) {
      # We could not connect, bail out for now
      return 0;
    }
    # Check that all mailboxes correspond to LDAP objects
    Kolab::log('L', 'Synchronising mailboxes');

    my @mailboxes = $cyrus->list('*');
    my %objects;
    my $mailbox;
    foreach $mailbox (@mailboxes) {
        my $u = @{$mailbox}[0];
        $u =~ /user[\/\.]([^\/]*)\/?.*/;
        $objects{$1} = 1 if ($1);
    }
    undef @mailboxes;

    my $guid;
    foreach $guid (keys %newuid_db) {
        delete $objects{$newuid_db{$guid}} if (exists $objects{$newuid_db{$guid}});
    }

    my $uid_db = uidcacheOpen();
    # Any mailboxes left should be sent to the graveyard; these are mailboxes
    # without a corresponding LDAP object, yet we were never informed of their
    # deletion, i.e. either we missed the deletion notification or there was
    # an error when iterating through the objects (Lost connection, invalid DNs)
    foreach $guid (keys %$uid_db) {
        if (defined $$uid_db{$guid} && exists $objects{$$uid_db{$guid}}) {
	    graveyardStore($guid, $$uid_db{$guid});
        }
    }
    uidcacheClose(%$uid_db);

    graveyardCleanup();

    my $newuid;
    foreach $newuid (keys %newuid_db) {
	uidcacheStore($newuid, $newuid_db{$newuid});
    }

    syncDomains();

    Kolab::log('L', 'Finished synchronisation');
}

# Date::Parse doesn't understand this format
# so we have to hack it ourselves
sub parse_generalized_time
{
  my $ts = shift;
  # YYYYMMDDHHMMSSZ
  if( $ts =~ /(\d\d\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z/ ) {
    my $t = 0;
    eval { $t = timegm($6,$5,$4,$3,$2-1,$1); };
    return $t;
  } else {
    return 0;
  }
}

# Returns the largest of two string-rep.
# of LDAP generalizedTime
sub max_generalized_time
{
  my $ts1 = shift;
  my $ts2 = shift;
  if( parse_generalized_time($ts1) >
      parse_generalized_time($ts2) ) { return $ts1; }
  else { return $ts2; }
}

sub syncBasic
{
    my $cyrus = shift;
    my $p = shift || 'user';
    my $add = shift || ($p eq 'user' ? '' : '');
    my $ts = shift || "";
    my $doacls = shift || 0;

    Kolab::log('L', "Synchronising `$p' objects");

    my $ldap = &create(
        $Kolab::config{$p . '_ldap_ip'},
        $Kolab::config{$p . '_ldap_port'},
        $Kolab::config{$p . '_bind_dn'},
        $Kolab::config{$p . '_bind_pw'}
    );

    my $ldapmesg;
    my $ldapobject;

    my @dnlist = split(/;/, $Kolab::config{$p . '_dn_list'});
    my $dn;

    foreach $dn (@dnlist) {
        Kolab::log('L', "Synchronising `$p' DN `$dn'");

        # First of all, remove any objects explicitly marked for deletion
        $ldapmesg = $ldap->search(
            base    => $dn,
            scope   => 'sub',
            filter  => '(&(objectClass=' . $Kolab::config{$p . '_object_class'} . ")$add(" . $Kolab::config{$p . '_field_deleted'} . '='.$Kolab::config{'fqdnhostname'}.'))',
            attrs   => [
                'objectClass',
                $Kolab::config{$p . '_field_guid'},
                $Kolab::config{$p . '_field_modified'},
                $Kolab::config{$p . '_field_deleted'},
            ],
        );

        if ( UNIVERSAL::isa( $ldapmesg, 'Net::LDAP::Search') && $ldapmesg->code() <= 0) {
	    while( $ldapobject = $ldapmesg->pop_entry ) {
                deleteObject($ldap, $cyrus, $ldapobject, 1, $p);
            }
        } else {
            Kolab::log('L', "Unable to locate deleted `$p' objects in DN `$dn'", KOLAB_WARN);
        }

        # Now check that all objects in LDAP have corresponding mailboxes
        # This also resurrects any missing users, if neccessary
	my $filter;
	if( $ts eq "" ) {
	  $filter = '(&(objectClass=' . $Kolab::config{$p . '_object_class'} . ")$add)",
	} else {
	  $filter = '(&(objectClass=' . $Kolab::config{$p . '_object_class'} . ")("
	    .$Kolab::config{$p.'_field_modified'}.">=$ts)$add)";
	}
	Kolab::log('L', "filter is $filter", KOLAB_DEBUG);
        $ldapmesg = $ldap->search(
            base    => $dn,
            scope   => 'sub',
            filter  => $filter,
            attrs   => [
                '*',
                $Kolab::config{$p . '_field_guid'},
		$Kolab::config{$p . '_field_modified'},
                $Kolab::config{$p . '_field_quota'},
                $Kolab::config{$p . '_field_deleted'},
            ],
        );

        if ( UNIVERSAL::isa( $ldapmesg, 'Net::LDAP::Search') && $ldapmesg->code() <= 0) {
	    while( $ldapobject = $ldapmesg->pop_entry ) {
                createObject($ldap, $cyrus, $ldapobject, 1, $p, $doacls);
		$ts = max_generalized_time($ts,$ldapobject->get_value($Kolab::config{$p . '_field_modified'}));
            }
        } else {
            Kolab::log('L', "Unable to locate `$p' objects in DN `$dn'", KOLAB_WARN);
        }

        Kolab::log('L', "Finished synchronising `$p' DN `$dn'");
    }

    &destroy($ldap);

    Kolab::log('L', "Finished `$p' object synchronisation");
    return $ts;
}

sub syncDomains
{
    Kolab::log('L', "Synchronising domains");

    my $ldapmesg;
    my $uid;
    my $ldapobject;
    my @domains;
    my $domain;

    my $ldap = &create(
        $Kolab::config{'ldap_ip'},
        $Kolab::config{'ldap_port'},
        $Kolab::config{'bind_dn'},
        $Kolab::config{'bind_pw'}
    );

    # If we have an old "cn=calendar" we need to fix the DN of that
    # object
    my $dn = 'cn=calendar,cn=internal,' . $Kolab::config{'base_dn'};
    $ldapmesg = $ldap->search(
        base    => 'cn=internal,' . $Kolab::config{'base_dn'},
        scope   => 'one',
	filter  => '(&(objectClass=kolabInetOrgPerson)(cn=calendar))',
            attrs   => [
                'objectClass',
                'uid',
	],
        );

    if ( UNIVERSAL::isa( $ldapmesg, 'Net::LDAP::Search') && $ldapmesg->count() > 0) {
        Kolab::log('L', "Identified old calendar user with DN `$dn'", KOLAB_DEBUG);
        my $cn = 'cn=' . $Kolab::config{'calendar_id'} . '@' . $Kolab::config{'postfix-mydomain'};
        $ldap->moddn($dn, newrdn => $cn, deleteoldrdn => 1);
        Kolab::log('L', "Renamed old calendar user with DN `$dn' to DN `$cn'", KOLAB_INFO);
    } else {
	Kolab::log('L', "Unable to locate old calendar user with DN `$dn'", KOLAB_DEBUG);
    }

    if( ref($Kolab::config{'postfix-mydestination'}) eq 'ARRAY' ) {
	@domains = @{$Kolab::config{'postfix-mydestination'}};
    } else {
	@domains =( $Kolab::config{'postfix-mydestination'} );
    }

    my $sha_pw = hash_pw($Kolab::config{'calendar_pw'});
    foreach $domain (@domains) {
	$uid = $Kolab::config{'calendar_id'} . '@' . $domain;
	$dn = 'cn=' . $uid . ',cn=internal,' . $Kolab::config{'base_dn'};
	$ldapmesg = $ldap->search(
	    base    => $dn,
	    scope   => 'one',
	    filter  => '(&(objectClass=kolabInetOrgPerson))',
            attrs   => [
                'objectClass',
                'uid',
	    ],
	    );
	if ( UNIVERSAL::isa( $ldapmesg, 'Net::LDAP::Search') && $ldapmesg->code() <= 0) {
	    Kolab::log('L', "Calendar user for domain `$domain' exists", KOLAB_DEBUG);
	} else {
	    $ldapobject = Net::LDAP::Entry->new;
	    $ldapobject->replace('cn' => $uid, 
				 'sn' => 'n/a n/a',
				 'uid' => $uid,
				 'userPassword' => $sha_pw, 
				 'objectclass' => ['top','inetorgperson','kolabinetorgperson']);
	    $ldapobject->dn($dn);
	    $ldapobject->update($ldap);
	    undef $ldapobject;
	    Kolab::log('L', "Created new calendar user with DN `$dn' for domain `$domain'", KOLAB_INFO);
	}
    }

}

# Taken from Samba::LDAP::User.pm
sub hash_pw {
    my $pass   = shift;

    # Generate SSHA hash (SHA1 with salt)
    my $salt = make_salt(4);
    return '{SSHA}' . encode_base64(sha1($pass . $salt) . $salt, '');
}

sub make_salt {
    my $self   = shift;
    my $length = shift || '32';

    my @tab = ('.', '/', 0 .. 9, 'A' .. 'Z', 'a' .. 'z');

    return join "", @tab[ map {rand 64} (1 .. $length) ];
}

sub ldap_error {
    my $mesg = shift;
    my $errstr = $mesg->dn || '';
    $errstr .= ": " if $errstr;
    $errstr .= $mesg->error if $mesg->error;
    Kolab::log('L', $errstr, KOLAB_ERROR);
}


1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Kolab::LDAP - Perl extension for generic LDAP code

=head1 ABSTRACT

  Kolab::LDAP contains functions used to create/delete objects,
  as well as synchronise LDAP and Cyrus.

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
