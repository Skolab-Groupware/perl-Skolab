package Skolab;

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
use Sys::Syslog;
use URI;
use Net::LDAP;
use Skolab::Util;
#use Skolab::LDAP;
use vars qw(%config);

require Exporter;

our @ISA = qw(Exporter);

our %EXPORT_TAGS = (
    'all' => [ qw(
        %config
        &reloadConfig
        &reload
        &log
    ) ]
);

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
    &SKOLAB_SILENT
    &SKOLAB_ERROR
    &SKOLAB_WARN
    &SKOLAB_INFO
    &SKOLAB_DEBUG
);

# The Skolab version number for the perl-skolab package
our $SKOLAB_BASE_VERSION = "2.4";

# Are current releases cvs based or is this a real release?
my $SKOLAB_GIT = 1;

our $SKOLAB_RELEASE = sprintf "%0004d%02d%02d", ((gmtime)[5] + 1900), ((gmtime)[4] + 1), (gmtime)[3];

if ($SKOLAB_GIT) {
    our $SKOLAB_VERSION = $SKOLAB_BASE_VERSION . "+git";
    our $VERSION = $SKOLAB_VERSION . $SKOLAB_RELEASE;
} else {
    our $SKOLAB_VERSION = $SKOLAB_BASE_VERSION;
    our $VERSION = $SKOLAB_VERSION;
}

sub SKOLAB_SILENT()      { 0 }
sub SKOLAB_ERROR()       { 1 }
sub SKOLAB_WARN()        { 2 }
sub SKOLAB_INFO()        { 3 }
sub SKOLAB_DEBUG()       { 4 }

sub reloadConfig
{
    my $skolab_globals = shift;
    my $globals_only = shift || 0;

    my $tempval;
    my $ldap;

    my $error = 0;
    my $ret = undef;

    # `log_level' specifies what severity of messages we want to see in the logs.
    #   Possible values are:
    #     0 - Silent
    #     1 - Errors
    #     2 - Warnings & Errors
    #     3 - Info, Warnings & Errors       (DEFAULT)
    #     4 - Debug (i.e. everything)

    # First read `skolab.globals'
    %config = readConfig(%config, $skolab_globals);

    # Return if we should only read the base information.
    if ($globals_only) {
       $ret = 1;
       return $ret;
    }

    # Determine the root of the skolab installation, and read `skolab.globals'
    # Notice that the location of the files is handled by dist_conf,
    # so we don't use $tempval for anything other than storing it in
    # $config{'prefix'}. Once prefix is not in use anywhere, we can remove
    # this code. /steffen
    $tempval = (getpwnam($config{'skolab_musr'}))[7];
    if (! defined $tempval) {
        $config{'log_level'} = SKOLAB_WARN;
        &log('C', 'Unable to determine the kolab user main directory', SKOLAB_ERROR);
        $ret = 0;
    }

    # Now read `skolab.conf', overwriting values read from `skolab.globals'
    %config = readConfig(\%config, $config{'skolab_locals'});

    $config{'debug'} = 0 if (!exists $config{'debug'});
    $config{'log_level'} = SKOLAB_WARN if (!exists $config{'log_level'});

    &log('C', 'Reloading configuration');

    # Get the UID/GID of the 'skolab' users
    $config{'skolab_uid'} = (getpwnam($config{'skolab_musr'}))[2];
    if (!defined $config{'skolab_uid'}) {
        &log('C', "Unable to determine the uid of user '$config{'skolab_musr'}'", SKOLAB_ERROR);
        $ret = 0;
    }

    $config{'skolab_gid'} = (getgrnam($config{'skolab_mgrp'}))[2];
    if (!defined $config{'skolab_gid'}) {
        &log('C', "Unable to determine the gid of user '$config{'skolab_mgrp'}'", SKOLAB_ERROR);
        $ret = 0;
    }

    $config{'skolab_n_uid'} = (getpwnam($config{'skolab_usr'}))[2];
    if (!defined $config{'skolab_n_uid'}) {
        &log('C', "Unable to determine the uid of user '$config{'skolab_usr'}", SKOLAB_ERROR);
        $ret = 0;
    }

    $config{'skolab_n_gid'} = (getgrnam($config{'skolab_grp'}))[2];
    if (!defined $config{'skolab_n_gid'}) {
        &log('C', "Unable to determine the gid of user $config{'skolab_grp'}", SKOLAB_ERROR);
        $ret = 0;
    }

    $config{'skolab_r_uid'} = (getpwnam($config{'skolab_rusr'}))[2];
    if (!defined $config{'skolab_r_uid'}) {
        &log('C', "Unable to determine the uid of user '$config{'skolab_rusr'}'", SKOLAB_ERROR);
        $ret = 0;
    }

    $config{'skolab_r_gid'} = (getgrnam($config{'skolab_rgrp'}))[2];
    if (!defined $config{'skolab_r_gid'}) {
        &log('C', "Unable to determine the gid of user '$config{'skolab_rgrp'}'", SKOLAB_ERROR);
        $ret = 0;
    }

    # Make sure the critical variables we need were defined in skolab.conf
    if (!exists $config{'bind_dn'} || !exists $config{'bind_pw'} || !exists $config{'ldap_uri'} || !exists $config{'base_dn'}) {
        &log('C', "One or more required configuration variables (`bind_dn', `bind_pw', `ldap_uri' and/or `base_dn') are missing in `skolab.conf'", SKOLAB_ERROR);
        $ret = 0;
    }

    # Make a hash of the bind password available too
    if( !exists $config{'bind_pw_hash'} ) {
      my $hashcmd = $config{'hashmethod'} . " '".$config{'bind_pw'}."'";
      $config{'bind_pw_hash'} = `$hashcmd`;
      chomp($config{'bind_pw_hash'});
    }

    # Retrieve the LDAP values of the main skolab object to complete our config hash
    if (!($tempval = URI->new($config{'ldap_uri'}))) {
        &log('C', "Unable to parse ldap_uri `" . $config{'ldap_uri'} . "'", SKOLAB_ERROR);
        $ret = 0;
    } else {
        $config{'ldap_ip'} = $tempval->host;
        $config{'ldap_port'} = $tempval->port;
    }

    # `skolab_dn' points to the main skolab object in LDAP
    #   Defaults to `k=skolab,$base_dn' if not specified (for backwards compatibility)
    $config{'skolab_dn'} = "k=skolab," . $config{'base_dn'} if (!exists $config{'skolab_dn'});
    if ($config{'skolab_dn'} eq '') {
        &log('C', "`skolab_dn' is empty; skipping LDAP read");
    } else {
        my $mesg;
        my $ldapobject;

        if (!($ldap = Net::LDAP->new($config{'ldap_uri'}, verify => 'none' ))) {
            &log('C', "Unable to connect to LDAP server `" . $config{'ldap_ip'} . ":" . $config{'ldap_port'} . "'", SKOLAB_ERROR);
            $ret = 0;
        }

        $mesg = $ldap->bind($config{'bind_dn'}, password => $config{'bind_pw'}) if $ldap;
        if ($ldap && $mesg->code) {
            &log('C', "Unable to bind to DN `" . $config{'bind_dn'} . "'", SKOLAB_ERROR);
            $ret = 0;
        }

        #$ldap = Skolab::LDAP::create(
        #    $config{'ldap_ip'},
        #    $config{'ldap_port'},
        #    $config{'bind_dn'},
        #    $config{'bind_pw'},
        #    1
        #);
        if ($ldap) {
            $mesg = $ldap->search(
                base    => $config{'skolab_dn'},
                scope   => 'base',
                filter  => '(objectclass=*)'
            );
            if (!$mesg->code) {
                $ldapobject = $mesg->pop_entry;
                foreach $tempval ($ldapobject->attributes) {
		    my $vals = $ldapobject->get_value($tempval, asref => 1 );
		    if( !ref($vals) ) {
		      # Not a ref at all???
                      &log('C', "Attribute $tempval does not exist", SKOLAB_WARN );
		    } elsif( @{$vals} == 1 ) {
		      $config{lc($tempval)} = $vals->[0];
		    } else {
		      $config{lc($tempval)} = $vals;
		    }
                }
            } else {
                &log('C', "Unable to find skolab object `" . $config{'skolab_dn'} . "'", SKOLAB_ERROR);
#                exit(1);
                $ret = 0;
            }
        } else {
            &log('C', "Unable to read configuration data from LDAP", SKOLAB_WARN);
        }
    }

    # At this point we have read in all user-specified configuration variables.
    # We now need to go through the list of all possible configuration variables
    # and set the default values of those that were not overridden.

    $config{'fqdn'} = trim(`hostname`);

    # connect to services at local address if binding to any interface,
    # otherwise use the address specified for the public interface.
    if ($config{'bind_any'} =~ /true/i) {
        $config{'connect_addr'} = $config{'local_addr'};
    } else {
        $config{'connect_addr'} = $config{'bind_addr'};
    }

    # Cyrus admin account
    $tempval = $config{'cyrus-admin'} || 'manager';
    (my $cmanager, my $dummy) = split(/ /, $tempval, 2);
    $config{'cyrus_admin'} = $cmanager if (!exists $config{'cyrus_admin'});
    $config{'cyrus_admin_pw'} = $config{'bind_pw'} if (!exists $config{'cyrus_admin_pw'});

    # `directory_mode' specifies what backend to use (for the main skolab
    # object - for the other objects see their respective XXX_directory_mode).
    # Defaults to `slurpd'
    #
    #   NOTE: A plugin scheme is used for this; the backend module loaded
    #   is `Skolab::LDAP::$config{'directory_mode'}, so anyone is able to slot
    #   in a new Skolab::LDAP:: module, change `directory_mode' and have the new
    #   module used as a backend (as long as it conforms to the correct
    #   interface, that is).
    #
    #   Currently supported backends:
    #     slurpd: for OpenLDAP 2.3.x and prior versions
    #     syncrepl: for OpenLDAP 2.3.x and beyond
    #     fds: Fedora Directory Server
    #     ad: Microsoft Active Directory
    $config{'directory_mode'} = 'slurpd' if (!exists $config{'directory_mode'});
    $config{'directory_replication_mode_is_syncrepl'} = 'TRUE' if ($config{'directory_mode'} eq 'syncrepl');
    if (($config{'directory_mode'} eq 'syncrepl') && !defined $config{'syncrepl_cookie_file'}) {
        &log('C', "Configuration variable `syncrepl_cookie_file' is missing ".
            "in `skolab.globals' or `skolab.globals' while using `syncrepl' directory_mode", SKOLAB_ERROR);
            $ret = 0;
    }

    # `conn_refresh_period' specifies how many minutes to wait before forceably
    # tearing down the change listener connection, re-syncing, and re-connecting.
    # Used by the AD backend.
    # Defaults to one hour.
#    $config{'conn_refresh_period'} = 60 if (!exists $config{'conn_refresh_period'});

    # `slurpd_port' specifies what port the skolab slurpd replication daemon listens on
    # Defaults to 9999 for backwards compatibility
#    $config{'slurpd_port'} = 9999 if (!exists $config{'slurpd_port'});

    # `user_ldap_uri', `user_bind_dn', `user_bind_pw' and `user_dn_list' are
    # used to specify the DNs where user objects are located. They default to
    # `ldap_uri', `bind_dn', `bind_pw' and `base_dn', respectively.
    #
    #   NOTE: `user_dn_list' is a semi-colon separated list of DNs, as opposed
    #   to a single DN (such as `skolab_dn').
    #
    #   TODO: Expand this to allow all separate entities (skolab object, users,
    #   shared folders, etc) to exist in user-specified locations
    #
    #   TODO: Check Postfix LDAP aliasing when user_dn_list contains more than
    #   one DN.
    $config{'user_ldap_uri'} = $config{'ldap_uri'} if (!exists $config{'user_ldap_uri'});

    if (!($tempval = URI->new($config{'user_ldap_uri'}))) {
        &log('C', "Unable to parse user_ldap_uri `" . $config{'user_ldap_uri'} . "'", SKOLAB_ERROR);
#        exit(1);
        $ret = 0;
    } else {
        $config{'user_ldap_ip'} = $tempval->host;
        $config{'user_ldap_port'} = $tempval->port;
    }

    $config{'user_bind_dn'} = $config{'bind_dn'} if (!exists $config{'user_bind_dn'});
    $config{'user_bind_pw'} = $config{'bind_pw'} if (!exists $config{'user_bind_pw'});
    $config{'user_dn_list'} = $config{'base_dn'} if (!exists $config{'user_dn_list'});
    $config{'user_directory_mode'} = $config{'directory_mode'} if (!exists $config{'user_directory_mode'});

    # `user_object_class' denotes what object class to search for when locating users.
    # Defaults to `inetOrgPerson'
    $config{'user_object_class'} = 'inetOrgPerson' if (!exists $config{'user_object_class'});

    # This part sets various backend-specific LDAP fields (if they have not been
    # overridden) based on `directory_mode'.
    #
    # `user_delete_flag' is used to test whether a user object has been deleted
    # `user_field_modified' is used to test whether a user object has been modified
    # `user_field_guid' indicates a field that can be considered globally unique to the object
    # `user_field_quota' indicates a field that stores the cyrus quota for the user
    if ($config{'user_directory_mode'} eq 'ad') {
        # AD
        $config{'user_field_deleted'} = 'isDeleted' if (!exists $config{'user_field_deleted'});
        $config{'user_field_modified'} = 'whenChanged' if (!exists $config{'user_field_modified'});
        $config{'user_field_guid'} = 'objectGUID' if (!exists $config{'user_field_guid'});
        $config{'user_field_quota'} = 'userquota' if (!exists $config{'user_field_quota'});
    } else {
        # slurd/default
        $config{'user_field_deleted'} = 'skolabdeleteflag' if (!exists $config{'user_field_deleted'});
        $config{'user_field_modified'} = 'modifytimestamp' if (!exists $config{'user_field_modified'});
        $config{'user_field_guid'} = 'entryUUID' if (!exists $config{'user_field_guid'});
        $config{'user_field_quota'} = 'cyrus-userquota' if (!exists $config{'user_field_quota'});

    }

    # The `sf_XXX' variables are the shared folder equivalents of the `user_XXX' variables
    $config{'sf_ldap_uri'} = $config{'ldap_uri'} if (!exists $config{'sf_ldap_uri'});

    if (!($tempval = URI->new($config{'sf_ldap_uri'}))) {
        &log('C', "Unable to parse sf_ldap_uri `" . $config{'sf_ldap_uri'} . "'", SKOLAB_ERROR);
#        exit(1);
        $ret = 0;
    } else {
        $config{'sf_ldap_ip'} = $tempval->host;
        $config{'sf_ldap_port'} = $tempval->port;
    }

    $config{'sf_bind_dn'} = $config{'bind_dn'} if (!exists $config{'sf_bind_dn'});
    $config{'sf_bind_pw'} = $config{'bind_pw'} if (!exists $config{'sf_bind_pw'});
    $config{'sf_dn_list'} = $config{'base_dn'} if (!exists $config{'sf_dn_list'});
    $config{'sf_directory_mode'} = $config{'directory_mode'} if (!exists $config{'sf_directory_mode'});

    $config{'sf_object_class'} = 'skolabsharedfolder' if (!exists $config{'sf_object_class'});

    if ($config{'sf_directory_mode'} eq 'ad') {
        # AD
        $config{'sf_field_deleted'} = 'isDeleted' if (!exists $config{'sf_field_deleted'});
        $config{'sf_field_modified'} = 'whenChanged' if (!exists $config{'sf_field_modified'});
        $config{'sf_field_guid'} = 'entryUUID' if (!exists $config{'sf_field_guid'});
        $config{'sf_field_quota'} = 'userquota' if (!exists $config{'sf_field_quota'});
    } else {
        # slurd/default
        $config{'sf_field_deleted'} = 'skolabdeleteflag' if (!exists $config{'sf_field_deleted'});
        $config{'sf_field_modified'} = 'modifytimestamp' if (!exists $config{'sf_field_modified'});
        $config{'sf_field_guid'} = 'entryUUID' if (!exists $config{'sf_field_guid'});
        $config{'sf_field_quota'} = 'cyrus-userquota' if (!exists $config{'sf_field_quota'});
    }

    # The `group_XXX' variables are the distribution list/groups 
    # equivalents of the `user_XXX' variables
    $config{'group_ldap_uri'} = $config{'ldap_uri'} if (!exists $config{'group_ldap_uri'});

    if (!($tempval = URI->new($config{'group_ldap_uri'}))) {
        &log('C', "Unable to parse group_ldap_uri `" . $config{'group_ldap_uri'} . "'", SKOLAB_ERROR);
#        exit(1);
        $ret = 0;
    } else {
        $config{'group_ldap_ip'} = $tempval->host;
        $config{'group_ldap_port'} = $tempval->port;
    }

    $config{'group_bind_dn'} = $config{'bind_dn'} if (!exists $config{'group_bind_dn'});
    $config{'group_bind_pw'} = $config{'bind_pw'} if (!exists $config{'group_bind_pw'});
    $config{'group_dn_list'} = $config{'base_dn'} if (!exists $config{'group_dn_list'});
    $config{'group_directory_mode'} = $config{'directory_mode'} if (!exists $config{'group_directory_mode'});

    $config{'group_object_class'} = 'skolabgroupofnames' if (!exists $config{'group_object_class'});

    if ($config{'group_directory_mode'} eq 'ad') {
        # AD
        $config{'group_field_deleted'} = 'isDeleted' if (!exists $config{'group_field_deleted'});
        $config{'group_field_modified'} = 'whenChanged' if (!exists $config{'group_field_modified'});
        $config{'group_field_guid'} = 'entryUUID' if (!exists $config{'group_field_guid'});
    } else {
        # slurd/default
        $config{'group_field_deleted'} = 'skolabdeleteflag' if (!exists $config{'group_field_deleted'});
        $config{'group_field_modified'} = 'modifytimestamp' if (!exists $config{'group_field_modified'});
        $config{'group_field_guid'} = 'entryUUID' if (!exists $config{'group_field_guid'});
    }

    # `gyard_deletion_period' specifies how many minutes to leave lost users in
    # the graveyard before deleting them.
    # Defaults to seven days.
#    $config{'gyard_deletion_period'} = 7 * 24 * 60 if (!exists $config{'gyard_deletion_period'});

    # That's it! We now have our config hash.
    #Skolab::LDAP::destroy($ldap);
    if (defined($ldap) && $ldap->isa('Net::LDAP')) {
        $ldap->unbind;
        $ldap->disconnect;
    }

    &log('C', 'Finished reloading configuration');
    if (!(defined($ret))) {
      # If it's still the initial value, i.e., undef, everything worked out
      # fine. Otherwise, it would be 0/false by now.
      $ret = 1;
    }

    return $ret;
}

sub log
{
    my $prefix = shift;
    my $text = shift;
    my $priority = shift || SKOLAB_INFO;

    if ($priority == SKOLAB_ERROR) {
        $text = $prefix . ' Error: ' . $text;
    } elsif ($priority == SKOLAB_WARN) {
        $text = $prefix . ' Warning: ' . $text;
    } elsif ($priority == SKOLAB_DEBUG) {
        $text = $prefix . ' Debug: ' . $text;
    } else {
        $text = $prefix . ': ' . $text;
    }
    syslog('info', "$text") if $config{'log_level'} >= $priority;
    print STDERR "$text\n" if $config{'debug'};
}

1;
__END__
=head1 NAME

Skolab - Perl extension for general Skolab settings.

=head1 ABSTRACT

  Skolab contains code used for loading the configuration values from
  skolab.conf and LDAP, as well as functions for logging.

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
