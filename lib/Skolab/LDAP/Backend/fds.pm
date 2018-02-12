package Skolab::LDAP::Backend::fds;

##
##  Copyright (c) 2003  Code Fusion cc, Stuart Bing� <s.binge@codefusion.co.za>
##  Copyright (c) 2007  Martin Konold <martin.konold@erfrakon.de>
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
use Skolab::Util;
use Skolab::LDAP;
use Net::LDAP;
use Net::LDAP::Control;
#use Mozilla::LDAP::API;
use vars qw($ldap $cyrus);

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

our $VERSION = '0.1';

sub startup { 1; }

sub shutdown
{
    Skolab::log('FDS', 'Shutting down');
    exit(0);
}

sub abort
{
    Skolab::log('FDS', 'Aborting');
    exit(1);
}

sub changeCallback
{
    Skolab::log('FDS', 'Change notification received', KOLAB_DEBUG);

    ###   $_[0]   isa     Net::LDAP::Message
    ###   $_[1]   shouldbea   Net::LDAP::Entry

    my $mesg = shift || 0;
    my $entry = shift || 0;

    my $issearch = $mesg->isa("Net::LDAP::Search");
    
    Skolab::log('FDS', "issearch=" . $issearch , KOLAB_DEBUG);
    if (!$issearch) {
    Skolab::log('FDS', 'mesg is not a search object, testing code...', KOLAB_DEBUG);
    if ($mesg->code == 88) {
        Skolab::log('FDS', 'changeCallback() -> Exit code received, returning', KOLAB_DEBUG);
        return;
    } elsif ($mesg->code) {
        Skolab::log('FDS', "mesg->code = `" . $mesg->code . "', mesg->msg = `" . $mesg->error . "'", KOLAB_DEBUG);
        &abort;
    }   
    } else {
    Skolab::log('FDS', 'mesg is a search object, not testing code', KOLAB_DEBUG);
    }

    Skolab::log('FDS', "entry=" . $entry , KOLAB_DEBUG);
    
    if (!$entry) {
    Skolab::log('FDS', 'changeCallback() called with a null entry', KOLAB_DEBUG);
    goto FOO;
    return;
    } elsif (!$entry->isa("Net::LDAP::Entry")) {
    Skolab::log('FDS', 'changeCallback() called with an invalid entry', KOLAB_DEBUG);
    return;
    }

    if (!Skolab::LDAP::isObject($entry, $Skolab::config{'user_object_class'}) &&
        !Skolab::LDAP::isObject($entry, 'kolab')) {
    Skolab::log('FDS', "Entry is not a `" . $Skolab::config{'user_object_class'} . "' or kolab configuration object, returning", KOLAB_DEBUG);
    return;
    }

FOO:
    Skolab::log('FDS', "Calling Skolab::LDAP::sync", KOLAB_DEBUG);
    Skolab::LDAP::sync;
    system($Skolab::config{'kolabconf_script'}) == 0 || Skolab::log('SD', "Failed to run kolabconf: $?", KOLAB_ERROR);
    Skolab::log('FDS', "Finished Skolab::LDAP::sync sleeping 1s", KOLAB_DEBUG);
    sleep 1; # we get too many bogus change notifications!

#    my $deleted = $entry->get_value($Skolab::config{'user_field_deleted'}) || 0;
#    if ($deleted) {
#    Skolab::LDAP::deleteObject($ldap, $cyrus, $entry);
#    return;
#    }
#
#    Skolab::LDAP::createObject($ldap, $cyrus, $entry);
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

  Skolab::log('FDS', 'Listener starting up');

  $cyrus = Skolab::Cyrus::create;

  Skolab::log('FDS', 'Cyrus connection established', KOLAB_DEBUG);

  while (1) {
    Skolab::log('FDS', 'Creating LDAP connection to FDS server', KOLAB_DEBUG);

    $ldap = Skolab::LDAP::create($Skolab::config{'user_ldap_ip'},
                                $Skolab::config{'user_ldap_port'},
                                $Skolab::config{'user_bind_dn'},
                                $Skolab::config{'user_bind_pw'},
                                1
                               );
    if (!$ldap) {
        Skolab::log('FDS', 'Sleeping 5 seconds...');
        sleep 5;
        next;
    }

    Skolab::log('FDS', 'LDAP connection established', KOLAB_DEBUG);

    Skolab::LDAP::ensureAsync($ldap);

    Skolab::log('FDS', 'Async checked', KOLAB_DEBUG);

    my $ctrl = Net::LDAP::Control->new(
    #    type    => '1.2.840.113556.1.4.528',
         type    => '2.16.840.1.113730.3.4.3',
        critical    => 'true'
    );

    Skolab::log('FDS', 'Control created', KOLAB_DEBUG);

    my @userdns = split(/;/, $Skolab::config{'user_dn_list'});
    my $userdn;

    Skolab::log('FDS', 'User DN list = ' . $Skolab::config{'user_dn_list'}, KOLAB_DEBUG);

    if (length(@userdns) == 0) {
    Skolab::log('FDS', 'No user DNs specified, exiting', KOLAB_ERROR);
    exit(1);
    }

    foreach $userdn (@userdns) {
      Skolab::log('FDS', "Registering change notification on DN `$userdn'");

      $mesg = $ldap->search (base     => $userdn,
                             scope    => 'one',
                             control  => [ $ctrl ],
                             callback => \&changeCallback,
                             filter   => '(objectClass=*)',
                             attrs    => [ '*',
                                           $Skolab::config{'user_field_guid'},
                                           $Skolab::config{'user_field_modified'},
                                           $Skolab::config{'user_field_quota'},
                                           $Skolab::config{'user_field_deleted'},
                                         ],
        );

#          $status = ldap_create_persistentsearch_control($ld,$changetypes,$changesonly,$return_echg_ctrls,$ctrl_iscritical,$ctrlp);

        Skolab::log('FDS', "Change notification registered on `$userdn'");
    }

    eval {
        local $SIG{ALRM} = sub {
        alarm 0;
        Skolab::log('FDS', 'Connection refresh period expired; tearing down connection');

        Skolab::LDAP::destroy($ldap);
        next;
        };

        Skolab::log('FDS', 'Waiting for changes (refresh period = ' . $Skolab::config{'conn_refresh_period'} . ' minutes)...');
        alarm $Skolab::config{'conn_refresh_period'} * 60;
        $mesg->sync;
        alarm 0;
    };
    }

    1;
}

1;
__END__

=head1 NAME

Skolab::LDAP::Backend::fds - Perl extension for Fedora Directory Server or Redhat Directory Server backend

=head1 ABSTRACT

  Skolab::LDAP::Backend::fds handles Fedora Directory Server or Redhat Directory Server backend to the
  kolab daemon.

=head1 AUTHOR

Martin Konold <lt>martin.konold@erfrakon.de<gt>
Stuart Bing� E<lt>s.binge@codefusion.co.za<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2003  Code Fusion cc
Copyright (c) 2007  Martin Konold, Erfrakon


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
