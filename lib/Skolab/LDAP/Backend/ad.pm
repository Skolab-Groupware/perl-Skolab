package Skolab::LDAP::Backend::ad;

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
use Kolab;
use Skolab::Util;
use Skolab::LDAP;
use Net::LDAP;
use Net::LDAP::Control;
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

our $VERSION = '0.9';

sub startup { 1; }

sub shutdown
{
    Skolab::log('AD', 'Shutting down');
    exit(0);
}

sub abort
{
    Skolab::log('AD', 'Aborting');
    exit(1);
}

sub changeCallback
{
    Skolab::log('AD', 'Change notification received', KOLAB_DEBUG);

    ###   $_[0]   isa     Net::LDAP::Message
    ###   $_[1]   shouldbea   Net::LDAP::Entry

    my $mesg = shift || 0;
    my $entry = shift || 0;

    my $issearch = $mesg->isa("Net::LDAP::Search");

    if (!$issearch) {
    Skolab::log('AD', 'mesg is not a search object, testing code...', KOLAB_DEBUG);
    if ($mesg->code == 88) {
        Skolab::log('AD', 'changeCallback() -> Exit code received, returning', KOLAB_DEBUG);
        return;
    } elsif ($mesg->code) {
        Skolab::log('AD', "mesg->code = `" . $mesg->code . "', mesg->msg = `" . $mesg->error . "'", KOLAB_DEBUG);
        &abort;
    }   
    } else {
    Skolab::log('AD', 'mesg is a search object, not testing code', KOLAB_DEBUG);
    }

    if (!$entry) {
    Skolab::log('AD', 'changeCallback() called with a null entry', KOLAB_DEBUG);
    return;
    } elsif (!$entry->isa("Net::LDAP::Entry")) {
    Skolab::log('AD', 'changeCallback() called with an invalid entry', KOLAB_DEBUG);
    return;
    }

    if (!Skolab::LDAP::isObject($entry, $Skolab::config{'user_object_class'})) {
    Skolab::log('AD', "Entry is not a `" . $Skolab::config{'user_object_class'} . "', returning", KOLAB_DEBUG);
    return;
    }

    my $deleted = $entry->get_value($Skolab::config{'user_field_deleted'}) || 0;
    if ($deleted) {
    Skolab::LDAP::deleteObject($ldap, $cyrus, $entry);
    return;
    }

    Skolab::LDAP::createObject($ldap, $cyrus, $entry);
}

sub run
{
    # This should be called from a separate thread, as we set our
    # own interrupt handlers here

    $SIG{'INT'} = \&shutdown;
    $SIG{'TERM'} = \&shutdown;

    END {
    alarm 0;
    Skolab::LDAP::destroy($ldap);
    }

    my $mesg;

    Skolab::log('AD', 'Listener starting up');

    $cyrus = Skolab::Cyrus::create;

    Skolab::log('AD', 'Cyrus connection established', KOLAB_DEBUG);

    while (1) {
    Skolab::log('AD', 'Creating LDAP connection to AD server', KOLAB_DEBUG);

    $ldap = Skolab::LDAP::create(
        $Skolab::config{'user_ldap_ip'},
        $Skolab::config{'user_ldap_port'},
        $Skolab::config{'user_bind_dn'},
        $Skolab::config{'user_bind_pw'},
        1
    );

    if (!$ldap) {
        Skolab::log('AD', 'Sleeping 5 seconds...');
        sleep 5;
        next;
    }

    Skolab::log('AD', 'LDAP connection established', KOLAB_DEBUG);

    Skolab::LDAP::ensureAsync($ldap);

    Skolab::log('AD', 'Async checked', KOLAB_DEBUG);

    my $ctrl = Net::LDAP::Control->new(
        type    => '1.2.840.113556.1.4.528',
        critical    => 'true'
    );

    Skolab::log('AD', 'Control created', KOLAB_DEBUG);

    my @userdns = split(/;/, $Skolab::config{'user_dn_list'});
    my $userdn;

    Skolab::log('AD', 'User DN list = ' . $Skolab::config{'user_dn_list'}, KOLAB_DEBUG);

    if (length(@userdns) == 0) {
    Skolab::log('AD', 'No user DNs specified, exiting', KOLAB_ERROR);
    exit(1);
    }

    foreach $userdn (@userdns) {
        Skolab::log('AD', "Registering change notification on DN `$userdn'");

        $mesg = $ldap->search (
        base    => $userdn,
        scope       => 'one',
        control     => [ $ctrl ],
        callback    => \&changeCallback,
        filter      => '(objectClass=*)',
        attrs   => [
            '*',
            $Skolab::config{'user_field_guid'},
            $Skolab::config{'user_field_modified'},
            $Skolab::config{'user_field_quota'},
            $Skolab::config{'user_field_deleted'},
        ],
        );

        Skolab::log('AD', "Change notification registered on `$userdn'");
    }

    eval {
        local $SIG{ALRM} = sub {
        alarm 0;
        Skolab::log('AD', 'Connection refresh period expired; tearing down connection');

        Skolab::LDAP::destroy($ldap);
        next;
        };

        Skolab::log('AD', 'Waiting for changes (refresh period = ' . $Skolab::config{'conn_refresh_period'} . ' minutes)...');
        alarm $Skolab::config{'conn_refresh_period'} * 60;
        $mesg->sync;
        alarm 0;
    };
    }

    1;
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Skolab::LDAP::Backend::ad - Perl extension for an Active Directory backend

=head1 ABSTRACT

  Skolab::LDAP::Backend::ad handles an Active Directory backend to the
  kolab daemon.

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
