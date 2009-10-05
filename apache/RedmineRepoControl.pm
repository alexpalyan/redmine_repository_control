package Apache::Authn::RedmineRepoControl;

=head1 Apache::Authn::RedmineRepoControl

Module for repository access and control to interface with Redmine

=head1 SYNOPSIS

=head1 INSTALLATION

=head1 CONFIGURATION

=cut

use strict;
use warnings FATAL => 'all', NONFATAL => 'redefine';

use DBI;
use Digest::SHA1;

# optional module for LDAP authentication
my $CanUseLDAPAuth = eval("use Authen::Simple::LDAP; 1");

use Apache2::Module;
use Apache2::Access;
use Apache2::ServerRec qw();
use Apache2::RequestRec qw();
use Apache2::RequestUtil qw();
use Apache2::Const qw(:common :override :cmd_how);
use APR::Pool();
use APR::Table();

my @directives = (
    {
        name         => 'RedmineDSN',
        req_override => OR_AUTHCFG,
        args_how     => TAKE1,
        errmsg       => 'DSN in format used by Perl DBI. eg: "DBI:Pg:dbname=databasename;host=my.db.server"',
    },
    {
        name         => 'RedmineDbUser',
        req_override => OR_AUTHCFG,
        args_how     => TAKE1,
    },
    { 
        name         => 'RedmineDbPass',
        req_override => OR_AUTHCFG,
        args_how     => TAKE1,
    },
    {
        name         => 'RedmineCacheCredsMax',
        req_override => OR_AUTHCFG,
        args_how     => TAKE1,
        errmsg => 'RedmineCacheCredsMax must be a decimal number',
    },
);

sub RedmineDSN {
    my ($self, $parms, $arg) = @_;
    $self->{RedmineDSN} = $arg;
    my $query = "SELECT 
    hashed_password, auth_source_id, permissions
    FROM members, projects, users, roles
    WHERE 
    projects.id=members.project_id 
    AND users.id=members.user_id 
    AND roles.id=members.role_id
    AND users.status=1 
    AND login=? 
    AND identifier=? ";
    $self->{RedmineQuery} = trim($query);
}

sub RedmineDbUser { set_val('RedmineDbUser', @_); }
sub RedmineDbPass { set_val('RedmineDbPass', @_); }
sub RedmineDbWhereClause { 
    my ($self, $parms, $arg) = @_;
    $self->{RedmineQuery} = trim($self->{RedmineQuery}.($arg ? $arg : "")." ");
}

sub RedmineCacheCredsMax { 
    my ($self, $parms, $arg) = @_;
    if ($arg) {
        $self->{RedmineCachePool} = APR::Pool->new;
        $self->{RedmineCacheCreds} = APR::Table::make($self->{RedmineCachePool}, $arg);
        $self->{RedmineCacheCredsCount} = 0;
        $self->{RedmineCacheCredsMax} = $arg;
    }
}

sub trim {
    my $string = shift;
    $string =~ s/\s{2,}/ /g;
    return $string;
}

sub set_val {
    my ($key, $self, $parms, $arg) = @_;
    $self->{$key} = $arg;
}

Apache2::Module::add(__PACKAGE__, \@directives);

# This is the list of all apache request methods that we are treating as "read-only" methods
my %read_only_methods = map { $_ => 1 } qw/GET PROPFIND REPORT OPTIONS/;

#
# Access is the first step in the AAA model. This funciton decides whether or not to even ask
# the user to log in. Basically, this is going to always be yes, however, if an anonymous
# person is trying to connect, and we've set that anonymous people can browse public projects
# then we will OK it, and tell apache that the authenicatin handler doesn't need to be called
# or, that the anonymous person doesn't need to log in.
#
sub access_handler {
    my $r = shift;

    my $cfg = Apache2::Module::get_config( __PACKAGE__, $r->server, $r->per_dir_config );

    unless ( $r->some_auth_required ) {
        $r->log_reason("No authentication has been configured");
        return FORBIDDEN;
    }

    #check public project AND anonymous access is allowed
    if ( !anonymous_denied($r) ) {
        my $project_id = get_project_identifier($r);
        my $project_pub = is_public_project( $project_id, $r );
        if ( $project_pub > 0 ) {
            # public project, so we check anonymous permissions
            # skip authen handler if anonymous is allowed
            if ( check_role_permissions('2', $r) == OK ) {
                #anonymous is allowed access
                $r->set_handlers( PerlAuthenHandler => [ \&OK ] );
                $r->set_handlers( PerlAuthzHandler => [ \&OK ] );
            }
        }
    }

    return OK;
}

# 
# This is the second step in the AAA model, Authentication. If we have gotten here, we need
# to make sure the user can authenticate against redmine. 
# 
sub authen_handler {
    my $r = shift;

    my $ret = AUTH_REQUIRED;

    my ($res, $redmine_pass) = $r->get_basic_auth_pw();
    return $res unless $res == OK;

    my $redmine_user = $r->user;
    my $project_id   = get_project_identifier($r);

    my $cfg = Apache2::Module::get_config(__PACKAGE__, $r->server, $r->per_dir_config);

    #1. Check the chache for the user's credentials
    my $usrprojpass;
    my $pass_digest = Digest::SHA1::sha1_hex($redmine_pass);
    if ($cfg->{RedmineCacheCredsMax}) {
        $usrprojpass = $cfg->{RedmineCacheCreds}->get($redmine_user.":".$project_id);
        return OK if ( defined $usrprojpass and ( $usrprojpass eq $pass_digest ));
    }

    #2. Otherwise, authenticate the user

    # Pull the hashed password for the user from the DB
    my $dbh          = connect_database($r);
    my $sth = $dbh->prepare("SELECT hashed_password, auth_source_id FROM users WHERE users.status=1 AND login=? ");
    $sth->execute($redmine_user);

    # check the result from the DB query to try and authenticate the user
    while ( my($hashed_password, $auth_source_id) = $sth->fetchrow_array ) {

        # if there is an auth_source_id set, then skip this first part and authenticate using the auth_source
        unless($auth_source_id) {
            # otherwise, authenticate using the hashed password
            if ( $hashed_password eq $pass_digest ) {
                $ret = OK;
            }
        } elsif ($CanUseLDAPAuth) {
            # pull the auth_source configuration from the database
            my $sthldap = $dbh->prepare("SELECT host,port,tls,account,account_password,base_dn,attr_login from auth_sources WHERE id = ?;");
            $sthldap->execute($auth_source_id);
            while (my @rowldap = $sthldap->fetchrow_array) {
                # add ldap authenticate as user
                my $bind_as = $rowldap[3];
                my $bind_pw = $rowldap[4] ? $rowldap[4] : "";
                if ($bind_as =~ m/\$login/) {
                    # if we have $login in the bind user, replace it with the user
                    # trying to log in, and use their password as well
                    $bind_as =~ s/\$login/$redmine_user/g;
                    $bind_pw = $redmine_pass;
                }
                
                my $ldap = Authen::Simple::LDAP->new(
                    host   => ($rowldap[2] == 1 || $rowldap[2] eq "t") ? "ldaps://$rowldap[0]" : $rowldap[0],
                    port   => $rowldap[1],
                    basedn => $rowldap[5],
                    binddn => $bind_as,
                    bindpw => $bind_pw,
                    filter => "(".$rowldap[6]."=%s)"
                );

                $ret = OK if ($ldap->authenticate($redmine_user, $redmine_pass));
            }

            $sthldap->finish();
        } else {
            #there is an auth_source, but we can't use it because we don't have the LDAP module installed,
            #so error and let the user know
            $r->log_error("Cannot load the Authen::Simple::LDAP module to authenticate the user, please check
               your installation");
            $ret = SERVER_ERROR;
        }
    } 

    $sth->finish();
    $dbh->disconnect();

    #
    # If the login was successful, add it to the cache
    #
    if ($cfg->{RedmineCacheCredsMax} and $ret) {
        if (defined $usrprojpass) {
            $cfg->{RedmineCacheCreds}->set($redmine_user.":".$project_id, $pass_digest);
        } else {
            if ($cfg->{RedmineCacheCredsCount} < $cfg->{RedmineCacheCredsMax}) {
                $cfg->{RedmineCacheCreds}->set($redmine_user.":".$project_id, $pass_digest);
                $cfg->{RedmineCacheCredsCount}++;
            } else {
                $cfg->{RedmineCacheCreds}->clear();
                $cfg->{RedmineCacheCredsCount} = 0;
            }
        }
    }

    $ret;
}

#
# This is the final stage in the AAA model, Authorization. This function decides
# whether or not the user is actually allowed to access this particular path by
# first checking the fine grain access crontrols, and then the more general role
# permissions. 
#
sub authz_handler {
    my $r = shift;
    my $ret = FORBIDDEN; # The default is to deny access

    my $redmine_user = $r->user;
    my $uri          = $r->uri;
    my $project_id   = get_project_identifier($r);
    my $req_path     = get_requested_path($r);
    my $dbh          = connect_database($r);

    ######################################################################
    #
    # 1. Check generic permissions for access
    #
    if ( check_role_permissions( '1', $r ) == OK ) {
        $ret = OK;
    }

    ######################################################################
    #
    # 2. Check the role the user belongs to in the project for permissions
    #
    my $sth = $dbh->prepare("SELECT roles.id FROM members, projects, users, roles
                    WHERE projects.id=members.project_id AND users.id=members.user_id
                    AND roles.id=members.role_id AND users.status=1 AND login=? AND identifier=?");
    $sth->execute($redmine_user, $project_id);
    while ( my($role_id) = $sth->fetchrow_array ) {
        $ret = check_role_permissions($role_id, $r);
    }

    $sth->finish();
    $dbh->disconnect();
    return $ret;
}

#
# Checks a roles permissions for a given role for the requested project
# 
sub check_role_permissions {
    my $role_id = shift;
    my $r = shift;

    my ($ret);

    my $redmine_user = $r->user;
    my $uri          = $r->uri;
    my $project_id   = get_project_identifier($r);
    my $req_path     = get_requested_path($r);
    my ($role_position);

    my $dbh          = connect_database($r);
    my $sth = $dbh->prepare("SELECT position, permissions FROM roles WHERE roles.id=?");

    $sth->execute($role_id);
    while ( my($position, $permissions) = $sth->fetchrow_array ) {
        # check default permissions then explicit permissions which 
        # will overwrite the default permissions

        $role_position = $position;

        if ( check_permission($permissions, $r) == OK ) {
            # the role has access to perform the requested operation
            $ret = OK;
        }
    }


    # now check if there is an explicit role definition 
    $sth = $dbh->prepare("SELECT roles.position, repository_controls.role_id, repository_controls.permissions, 
        repository_controls.path FROM repository_controls, projects, roles
        WHERE projects.id=repository_controls.project_id 
        AND roles.id=repository_controls.role_id 
        AND identifier=?");
    $sth->execute($project_id);

    # check the result from the DB query to try and authenticate the user
    while ( my($position, $id, $permission, $path) = $sth->fetchrow_array ) {
        if ( $req_path =~ m{$path} ) {
            if ( $position < $role_position ) {
                # There is a specific permission defined for a higher level role, deny this role
                $ret = FORBIDDEN;
           } elsif ( !defined($ret) or $ret != FORBIDDEN ) {
                if ( check_permission($permission, $r) == OK ) {
                    # user has explicit permission to perform the action requested
                    $ret = OK;
                } else {
                    # otherwise it has been explicity denied
                    $ret = FORBIDDEN;
                }
            }
        }
    } 

    if ( !defined($ret) ) {
        $ret = FORBIDDEN;
    }

    $sth->finish();
    $dbh->disconnect();
    return $ret;

}

#
# Returns the path requested in the repository
#
sub get_requested_path {
    my $r = shift;

    my $location = $r->location;
    my ($path) = $r->uri =~ m{$location/*[^/]+(/.*)};

    $path
}

# 
# Returns the project identifier for a given request
#
sub get_project_identifier {
    my $r = shift;

    my $location = $r->location;
    my ($identifier) = $r->uri =~ m{$location/*([^/]+)};
    $identifier;
}

#
# Returns a connection to the database
#
sub connect_database {
    my $r = shift;

    my $cfg = Apache2::Module::get_config( __PACKAGE__, $r->server, $r->per_dir_config );
    return DBI->connect( $cfg->{RedmineDSN}, $cfg->{RedmineDbUser},$cfg->{RedmineDbPass} );
}

# Checks a given permission against the request method. If the request to apache
# is in the $read_only_methods list, then we only need to see that the permission
# given is :browse_repository. Otherwise, it is a write request, and the permission
# needs to be :commit_access
sub check_permission() {
    my $perm = shift;
    my $r    = shift;


    if ( defined $read_only_methods{ $r->method } ) {
        #$r->log_error("Checking permission '$perm' for read access");
        return OK if ( $perm =~ /:browse_repository/ );
    } else {
        #$r->log_error("Checking permission '$perm' for write access");
        return OK if ( $perm =~ /:commit_access/ );
    }

    return FORBIDDEN;
}

#
# Pulls a user's permissions for a given project. This uses the RedmineQuery
# setup in the RedmineDSN function to pull all of the permissions that are 
# granted to the role that a user belongs to in a project. It then returns
# those permissions in a single list @ret
#
sub get_user_permissions {
    my $redmine_user = shift;
    my $project_id   = shift;
    my $r            = shift;

    my $cfg = Apache2::Module::get_config(__PACKAGE__, $r->server, $r->per_dir_config);

    my $dbh = connect_database($r);
    my $sth = $dbh->prepare( $cfg->{RedmineQuery} );

    $sth->execute( $redmine_user, $project_id );
    my @ret;
    while ( my ($it) = $sth->fetchrow_array ) {
        push( @ret, $it );
    }
    $sth->finish();
    $dbh->disconnect();

    @ret;
}

#
# Retrieves the permissions for anonymous users. These permissions are the
# same for all projects. The permissions are returned in a single list @ret
#
sub get_anonymous_permissions {
    my $r = shift;

    my $dbh = connect_database($r);
    my $sth = $dbh->prepare("SELECT permissions FROM roles WHERE roles.id=2");

    $sth->execute();
    my ($ret) = $sth->fetchrow_array;
    $sth->finish();
    $dbh->disconnect();

    $ret;
}

#
# Returns true if the "login_required" box is checked for authentication inside
# the redmine administration->settings->authentication page. This will disable
# anonymous users from accessing repositories, even if anonymous has the
# :browse_repository or :commit_access permissions set.
#
sub anonymous_denied {
    my $r = shift;

    my $dbh = connect_database($r);
    my $sth =
    $dbh->prepare("SELECT value FROM settings WHERE name='login_required'");

    $sth->execute();
    my ($ret) = $sth->fetchrow_array;
    $sth->finish();
    $dbh->disconnect();

    $ret;
}

sub is_public_project {
    my $project_id = shift;
    my $r = shift;

    my $dbh = connect_database($r);
    my $sth = $dbh->prepare(
        "SELECT * FROM projects WHERE projects.identifier=? and projects.is_public=true;"
    );

    $sth->execute($project_id);
    my $ret = $sth->fetchrow_array ? 1 : 0;
    $sth->finish();
    $dbh->disconnect();

    $ret;
}

1;
