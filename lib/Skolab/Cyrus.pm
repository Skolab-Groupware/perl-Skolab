package Skolab::Cyrus;

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
use Cyrus::IMAP::Admin;
use Skolab::Util;
use Kolab;

require Exporter;

our @ISA = qw(Exporter);

our %EXPORT_TAGS = (
    'all' => [ qw(
        &create
        &createUid
        &createMailbox
        &createCalendar
        &deleteMailbox
        &setQuota
        &setACL
    ) ]
);

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(

);

our $VERSION = '0.9';

sub create
{
    Skolab::log('Y', 'Connecting to local Cyrus admin interface');

    my $cyrus = Cyrus::IMAP::Admin->new($Skolab::config{'connect_addr'});

    if (!$cyrus) {
        Skolab::log('Y', 'Unable to connect to local Cyrus admin interface', KOLAB_ERROR);
	return 0;
    }

    if (!$cyrus->authenticate(
        'User'          => $Skolab::config{'cyrus_admin'},
        'Password'      => $Skolab::config{'cyrus_admin_pw'},
        'Mechanism'    => 'LOGIN',
    )) {
        Skolab::log('Y', "Unable to authenticate with Cyrus admin interface, Error = `" . $cyrus->error . "'", KOLAB_ERROR);
	return 0;
    }

    return $cyrus;
}

sub createUid
{
    my $user = shift;
    my $sf = shift || 0;
    my $seperator = '/';
    my $uidprefix = 'user';
    if ($sf) { 
      $seperator = '.'; 
      $uidprefix = 'shared';
    } 
    return $uidprefix . $seperator . $user;
#    return 'user' . ($sf ? '.' : '/') . $user;
}

sub createMailbox
{
    my $cyrus = shift;
    my $uid = shift;
    my $sf = shift || 0;
    my $partition = shift || '';

    my $cyruid = &createUid($uid, $sf);
    my $mailbox = ($cyrus->list($cyruid))[0];
    if ($uid && ($uid ne $Skolab::config{'cyrus_admin'}) && ($uid ne "freebusy") && ($uid ne "nobody") && !defined($mailbox)) {
        Skolab::log('Y', "Creating mailbox `$cyruid' on ".($partition?"partition `$partition'":"default partition"));
        if (!$cyrus->create($cyruid, $partition)) {
            Skolab::log('Y', "Unable to create mailbox `$cyruid', Error = `" . $cyrus->error . "'", KOLAB_WARN);
        }
    } else {
        Skolab::log('Y', "Skipping mailbox creation for $uid (curuid='$cyruid', mailbox='".join(',',@{$mailbox})."'", KOLAB_DEBUG);
    }
}

sub createCalendar
{
    my $cyrus = shift;
    my $user = shift;
    my $domain = shift;
    my $folder = shift;
    my $acl = shift;

    my $calendar = 0;

    my @mailboxes = $cyrus->list("user/$user/*\@$domain");
    my %info;
    foreach my $mailbox (@mailboxes) {
	my $u = @{$mailbox}[0];
	%info = $cyrus->info($u, ('/vendor/kolab/folder-type'));
	my $key = '/mailbox/{' . $u . '}/vendor/kolab/folder-type';
	if (exists($info{$key}) && $info{$key} eq 'event.default') {
	    $calendar = $u;
	}
    }

    if ($calendar) {
        Skolab::log('Y', "Skipping calendar creation for $user\@$domain as $calendar is a default calendar.", KOLAB_DEBUG);
    } else {
        Skolab::log('Y', "Creating default calendar for $user\@$domain.", KOLAB_DEBUG);
	createMailbox($cyrus, $folder, 0);
	setFolderType($cyrus, $folder, 0, 'event.default');
	setACL($cyrus, $folder, 0, $acl);
        Skolab::log('Y', "Successfully created default calendar for $user\@$domain.", KOLAB_DEBUG);
    }
}

sub setQuota
{
    my $cyrus = shift;
    my $uid = shift;
    my $quota = shift || 0;
    my $sf = shift || 0;
    my $cyruid = &createUid($uid, $sf);

    if( $quota < 0 ) {
	return;
    }

    (my $root, my %quota) = $cyrus->quotaroot($cyruid);
    my $setquota = $quota{'STORAGE'}[1];

    if (!defined($setquota) || ($setquota != $quota)) {
      if( $quota == 0 ) {
	Skolab::log('Y', "Removing quota from mailbox `$cyruid'");
	if (!$cyrus->setquota($cyruid)) {
	  Skolab::log('Y', "Unable to remove quota for mailbox `$cyruid', Error = `" . $cyrus->error . "'", KOLAB_WARN);
	}
      } else {
	Skolab::log('Y', "Setting quota of mailbox `$cyruid' to $quota");
	if (!$cyrus->setquota($cyruid, 'STORAGE', $quota)) {
	  Skolab::log('Y', "Unable to set quota for mailbox `$cyruid', Error = `" . $cyrus->error . "'", KOLAB_WARN);
	}
      }
    }
}

sub deleteMailbox
{
    my $cyrus = shift;
    my $uid = shift;
    my $sf = shift || 0;
    my $cyruid = &createUid($uid, $sf);

    Skolab::log('Y', "Removing mailbox `$cyruid'");
    if (!$cyrus->setacl($cyruid, $Skolab::config{'cyrus_admin'}, 'c')) {
        Skolab::log('Y', "Unable to reset ACL of mailbox `$cyruid', Error = `" . $cyrus->error . "'", KOLAB_WARN);
    }
    if (!$cyrus->delete($cyruid)) {
        Skolab::log('Y', "Unable to remove mailbox `$cyruid', Error = `" . $cyrus->error . "'", KOLAB_WARN);
    }
}

sub setACL
{
    my $cyrus = shift;
    my $uid = shift;
    my $sf = shift || 0;
    my $cyruid = &createUid($uid, $sf);

    Skolab::log('Y', "Setting up ACL of mailbox `$cyruid'");
    my %acls = $cyrus->listacl( $cyruid );
    my ($user, $entry, $acl);
    Skolab::log('Y', "Removing users from ACL of $cyruid (users are \"".join(', ', keys %acls)."\")", KOLAB_DEBUG);
    foreach $user ( keys %acls) {
        Skolab::log('Y', "Removing `$user' from the ACL of mailbox `$cyruid'");
        if (!$cyrus->deleteacl($cyruid, $user)) {
            Skolab::log('Y', "Unable to remove `$user' from the ACL of mailbox `$cyruid', Error = `" . $cyrus->error . "'", KOLAB_WARN);
        }
    }

    Skolab::log('Y', "Add users from ACL of $cyruid", KOLAB_DEBUG);
    my $newacl = shift;
    foreach $entry (@$newacl) {
        Skolab::log('Y', "Setting up ACL `$entry'", KOLAB_DEBUG);
        ($user, $acl) = split(/ /, $entry , 2);
        Skolab::log('Y', "Split `$user' and `$acl'", KOLAB_DEBUG);
        $user = trim($user);
        $acl = trim($acl);
        Skolab::log('Y', "Setting the ACL of user `$user' in mailbox `$cyruid' to $acl");
        if (!$cyrus->setacl($cyruid, $user, $acl)) {
            Skolab::log('Y', "Unable to set the ACL of user `$user' in mailbox `$cyruid' to $acl, Error = `" . $cyrus->error . "'", KOLAB_WARN);
        }
    }
    Skolab::log('Y', "Finished modifying ACL of $cyruid", KOLAB_DEBUG);
}

sub setFolderType {
  my $cyrus = shift;
  my $uid = shift;
  my $sf = shift || 0;
  my $foldertype = shift || 'mail';
  my $cyruid = &createUid($uid, $sf);
    
  if (!$cyrus->mboxconfig($cyruid, '/vendor/kolab/folder-type', $foldertype)) {
    Skolab::log('Y', "Unable to set the folder type for mailbox `$cyruid' to `$foldertype', Error = `" . $cyrus->error . "'", KOLAB_WARN);
  }
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Skolab::Cyrus - Perl extension for interfacing with the Kolab Cyrus
admin module.

=head1 ABSTRACT

  Skolab::Cyrus contains cyrus-related functions, such as
  adding/deleting mailboxes, etc.

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
