package Skolab::LDAP::Backend::syncrepl;

##
##  Copyright (c) 2008  Mathieu Parent <math.parent@gmail.com>
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
use 5.008;
use strict;
use warnings;
use Kolab;
use Skolab::LDAP;
use Net::LDAP qw(
	LDAP_USER_CANCELED
	LDAP_SYNC_REFRESH_ONLY
	LDAP_SYNC_REFRESH_AND_PERSIST
);
use Net::LDAP::Control;
use Net::LDAP::Control::SyncRequest;
use Net::LDAP::Entry;
use vars qw($ldap $disconnected);
my $disconnected = 1;

require Exporter;

our @ISA = qw(Exporter);

our %EXPORT_TAGS = (
    'all' => [ qw(
    &startup
    &run
    ) ]
);

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
    
);

our $VERSION = '0.3';

sub mode { 
  LDAP_SYNC_REFRESH_ONLY;
  #LDAP_SYNC_REFRESH_AND_PERSIST;
}

# calling without args means: get,
# giving an argument means: set
sub cookie {
  my($cookie) = @_;
  my $syncrepl_cookie_file = $Skolab::config{'syncrepl_cookie_file'} || '/tmp/kolab_syncrepl_cookie_file';
  if(defined($cookie)) {
    if(!open(COOKIE_FILE, '>', $syncrepl_cookie_file)) {
        Skolab::log("SYNCREPL', 'Cannot open file `".$syncrepl_cookie_file.
        "' for writing: $!", KOLAB_DEBUG);
        &abort;
    }
    Skolab::log("SYNCREPL', 'Writing cookie to file: ".$cookie, KOLAB_DEBUG);
    print COOKIE_FILE $cookie;
    close(COOKIE_FILE);
    return $cookie;
  } else {
    #create if it doesn't exists
    if(! -f $syncrepl_cookie_file) {
        open COOKIE_FILE, '>', $syncrepl_cookie_file;
        close COOKIE_FILE;
    }
    if(!open(COOKIE_FILE, '+<', $syncrepl_cookie_file)) {
        Skolab::log("SYNCREPL', 'Cannot open file `".$syncrepl_cookie_file.
        "' for reading: $!", KOLAB_DEBUG);
        &abort;
    }
    read COOKIE_FILE, $cookie, 1024, 0;
    close COOKIE_FILE;
    #an empty file means no cookie:
    $cookie = undef if !$cookie;
    return $cookie;
  }
}

sub startup { 1; }

sub shutdown
{
  Skolab::log('SYNCREPL', 'Shutting down');
  exit(0);
}

sub abort
{
    Skolab::log('SYNCREPL', 'Aborting');
    exit(1);
}

sub run {
  # This should be called from a separate thread, as we set our
  # own interrupt handlers here

  $SIG{'INT'} = \&shutdown;
  $SIG{'TERM'} = \&shutdown;

  END {
    alarm 0;
    Skolab::LDAP::destroy($ldap);
  }
  my $mesg;

  while (1) {
    Skolab::log('SYNCREPL', 'Creating LDAP connection to LDAP server', KOLAB_DEBUG);

    $ldap = Skolab::LDAP::create($Skolab::config{'user_ldap_ip'},
                                $Skolab::config{'user_ldap_port'},
                                $Skolab::config{'user_bind_dn'},
                                $Skolab::config{'user_bind_pw'},
                                1
                               );
    if (!$ldap) {
        Skolab::log('SYNCREPL', 'Sleeping 5 seconds...');
        sleep 5;
        next;
    }
    $disconnected = 0;  

    Skolab::log('SYNCREPL', 'LDAP connection established', KOLAB_DEBUG);

    Skolab::LDAP::ensureAsync($ldap);
    Skolab::log('SYNCREPL', 'Async checked', KOLAB_DEBUG);

    while($ldap and not $disconnected) {
      my $ctrl = Net::LDAP::Control::SyncRequest->new(
        mode       => Skolab::LDAP::Backend::syncrepl::mode(),
        cookie     => Skolab::LDAP::Backend::syncrepl::cookie(),
        reloadHint => 0);
      Skolab::log('SYNCREPL', 'Control created: mode='.$ctrl->mode().
      	'; cookie='.$ctrl->cookie().
      	'; reloadHint='.$ctrl->reloadHint(), KOLAB_DEBUG);

      #search
      my $mesg = $ldap->search(base     => $Skolab::config{'base_dn'},
                               scope    => 'sub',
                               control  => [ $ctrl ],
                               callback => \&searchCallback, # call for each entry
                               filter   => "(objectClass=*)",
                               attrs    => [ '*',
                                             $Skolab::config{'user_field_guid'},
                                             $Skolab::config{'user_field_modified'},
                                             $Skolab::config{'user_field_quota'},
                                             $Skolab::config{'user_field_deleted'},
                                           ],
                              );
      Skolab::log('SYNCREPL', 'Search created', KOLAB_DEBUG);
      $mesg->sync;
      Skolab::log('SYNCREPL', "Finished Net::LDAP::Search::sync sleeping 10s", KOLAB_DEBUG);
      sleep 10;
    }
  }
  1;
}

#search callback
sub searchCallback {
  my $mesg = shift;
  my $param2 = shift; # might be entry or intermediate
  my @controls = $mesg->control;
  my @sync_controls = ();
  if($param2 && $param2->isa("Net::LDAP::Entry")) {
    Skolab::log('SYNCREPL', 'Received Search Entry', KOLAB_DEBUG);
    #retrieve Sync State Control
    foreach my $ctrl (@controls) {
      push(@sync_controls, $ctrl)
        if $ctrl->isa('Net::LDAP::Control::SyncState');
    }
    if(@sync_controls>1) {
      Skolab::log('SYNCREPL', 'Got search entry with multiple Sync State controls',
        KOLAB_DEBUG);
      return;
    }
    if(!@sync_controls) {
      Skolab::log('SYNCREPL', 'Got search entry without Sync State control',
        KOLAB_DEBUG);
      return;
    }
    if(!$sync_controls[0]->entryUUID) {
      Skolab::log('SYNCREPL', 'Got empty entryUUID', KOLAB_DEBUG);
      return;
    }
    Skolab::log('SYNCREPL', 'Search Entry has Sync State Control: '.
      'state='.$sync_controls[0]->state().
      '; entryUUID='.unpack("H*",$sync_controls[0]->entryUUID()).
      '; cookie='.(defined($sync_controls[0]->cookie()) ? $sync_controls[0]->cookie() : 'UNDEF')
	, KOLAB_DEBUG);
    if(defined($sync_controls[0]->cookie)) {
      Skolab::LDAP::Backend::syncrepl::cookie($sync_controls[0]->cookie);
      Skolab::log('SYNCREPL',"New cookie: ".Skolab::LDAP::Backend::syncrepl::cookie(),
        KOLAB_DEBUG);
    }
    Skolab::log('SYNCREPL', "Entry (".$param2->changetype."): ".$param2->dn(), KOLAB_DEBUG);
  } elsif($param2 && $param2->isa("Net::LDAP::Reference")) {
    Skolab::log('SYNCREPL', 'Received Search Reference', KOLAB_DEBUG);
    return;
  #if it not first control?
  } elsif($controls[0] and $controls[0]->isa('Net::LDAP::Control::SyncDone')) {
    Skolab::log('SYNCREPL', 'Received Sync Done Control: '.
      'cookie='.(defined($controls[0]->cookie()) ? $controls[0]->cookie() : 'UNDEF').
      '; refreshDeletes='.$controls[0]->refreshDeletes(), KOLAB_DEBUG);
    #we have a new cookie
    if(defined($controls[0]->cookie())
        and not $controls[0]->cookie() eq '' 
        and not $controls[0]->cookie() eq Skolab::LDAP::Backend::syncrepl::cookie()) {
      Skolab::LDAP::Backend::syncrepl::cookie($controls[0]->cookie());
      Skolab::log('SYNCREPL', "New cookie: ".
        Skolab::LDAP::Backend::syncrepl::cookie(), KOLAB_DEBUG);
      Skolab::log('SYNCREPL', "Calling Skolab::LDAP::sync", KOLAB_DEBUG);
      Skolab::LDAP::sync;
      system($Skolab::config{'kolabconf_script'}) == 0
        || Skolab::log('SD', "Failed to run kolabconf: $?", KOLAB_ERROR);
      Skolab::log('SYNCREPL', "Finished Skolab::LDAP::sync sleeping 1s", KOLAB_DEBUG);
      sleep 1; # we get too many bogus change notifications!
	  } 
  } elsif($param2 && $param2->isa("Net::LDAP::Intermediate")) {
    Skolab::log('SYNCREPL', 'Received Intermediate Message', KOLAB_DEBUG);
    my $attrs = $param2->{asn};
    if($attrs->{newcookie}) {
      Skolab::LDAP::Backend::syncrepl::cookie($attrs->{newcookie});
      Skolab::log('SYNCREPL', "New cookie: ".
        Skolab::LDAP::Backend::syncrepl::cookie(), KOLAB_DEBUG);
    } elsif(my $refreshInfos = ($attrs->{refreshDelete} || $attrs->{refreshPresent})) {
      Skolab::LDAP::Backend::syncrepl::cookie($refreshInfos->{cookie})
        if defined($refreshInfos->{cookie});
      Skolab::log('SYNCREPL', 
        (defined($refreshInfos->{cookie}) ? 'New ' : 'Empty ').
        "cookie from ".
        ($attrs->{refreshDelete} ? 'refreshDelete' : 'refreshPresent').
        " (refreshDone=".$refreshInfos->{refreshDone}."): ".
        Skolab::LDAP::Backend::syncrepl::cookie(), KOLAB_DEBUG);
    } elsif(my $syncIdSetInfos = $attrs->{syncIdSet}) {
      Skolab::LDAP::Backend::syncrepl::cookie($syncIdSetInfos->{cookie})
        if defined($syncIdSetInfos->{cookie});
      Skolab::log('SYNCREPL', 
        (defined($syncIdSetInfos->{cookie}) ? 'Empty ' : 'New ').
        "cookie from syncIdSet".
        " (refreshDeletes=".$syncIdSetInfos->{refreshDeletes}."): ".
        Skolab::LDAP::Backend::syncrepl::cookie(), KOLAB_DEBUG);
      foreach my $syncUUID ($syncIdSetInfos->{syncUUIDs}) {
        Skolab::log('SYNCREPL', 'entryUUID='.
          unpack("H*",$syncUUID), KOLAB_DEBUG);
      }
    }
  } elsif($mesg->code) {
    if ($mesg->code == 1) {
      Skolab::log('SYNCREPL', 'Communication Error: disconnecting', KOLAB_DEBUG);
      $disconnected = 1;
      return 0;
    } elsif ($mesg->code == LDAP_USER_CANCELED) {
        Skolab::log('SYNCREPL', 'searchCallback() -> Exit code received, returning', KOLAB_DEBUG);
        return;
    } elsif ($mesg->code == 4096) {
        Skolab::log('SYNCREPL', 'Refresh required', KOLAB_DEBUG);
        Skolab::LDAP::Backend::syncrepl::cookie('');
    } else {
        Skolab::log('SYNCREPL', "searchCallback: mesg->code = `" . $mesg->code . "', mesg->msg = `" . $mesg->error . "'", KOLAB_DEBUG);
        &abort;
    }   
  } else {
    Skolab::log('SYNCREPL', 'Received something else', KOLAB_DEBUG);
  }
  return 0;
}

1;
__END__

=head1 NAME

Skolab::LDAP::Backend::syncrepl - Perl extension for RFC 4533 compliant LDAP server backend

=head1 ABSTRACT

  Skolab::LDAP::Backend::syncrepl handles OpenLDAP backend to the kolab daemon.

=head1 AUTHOR

Mathieu Parent <math.parent@gmail.com>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2008  Mathieu Parent <math.parent@gmail.com>


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

=head1 NOTES
We use refreshOnly mode as refreshAndPersist mode uses LDAP Intermediate
Response Messages [RFC4511] that are not supported by current Net::LDAP.

However (quoting from RFC, page 21):

   The server SHOULD transfer a new cookie frequently to avoid having to
   transfer information already provided to the client.  Even where DIT
   changes do not cause content synchronization changes to be
   transferred, it may be advantageous to provide a new cookie using a
   Sync Info Message.  However, the server SHOULD avoid overloading the
   client or network with Sync Info Messages.



=cut
