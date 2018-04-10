use strict;
use warnings;

package Authen::Passphrase::Argon2;

# ABSTRACT: Argon2 support for Authen::Passphrase

use parent 'Authen::Passphrase';
use Carp;
use Crypt::Argon2 qw( argon2id_pass argon2id_verify );
use Syntax::Construct qw( ?<> /a );

our @_attr = qw(passphrase salt t_cost m_factor parallelism tag_size);

sub new {
    my $class = shift;
    my $self = bless( {}, $class );

    while (@_) {
        my $attr  = shift;
        my $value = shift;
        $self->{$attr} = $value;
    }

    if ( !defined $self->{_hash} ) {
        for (@_attr) {
            croak "$_ not set" unless defined $self->{$_};
        }

        my $hash = argon2id_pass(map {$self->{$_}} @_attr);
        $self->{_hash} = $hash;
    }

    return $self;
}

sub from_crypt {
    my ( $class, $crypt ) = @_;

    croak "invalid Argon2 crypt format"
        unless $crypt =~ m/^
            \$argon2id
            \$v=\d+
            \$m=(?<m_factor>\d+),
            t=(?<t_cost>\d+),
            p=(?<parallelism>\d+)
            \$
        /ax;

    return $class->new(%+, _hash => $crypt);
}

sub from_rfc2307 {
    my ( $class, $rfc2307 ) = @_;
    my ($hash) = $rfc2307 =~ m/^{ARGON2}(.*)$/;
    croak "invalid Argon2 RFC2307 format" unless $hash;

    return $class->from_crypt($hash);
}

sub match {
    my ( $self, $passphrase ) = @_;
    return argon2id_verify( $self->{_hash}, $passphrase );
}

sub as_crypt {
    my $self = shift;
    return $self->{_hash};
}

sub as_rfc2307 {
    my $self = shift;
    return '{ARGON2}' . $self->{_hash};
}

=head1 SYNOPSIS

use Authen::Passphrase::Argus2;

# hash a password
my $ppr = Authen::Passphrase::Argon2->new(
    passphrase  => 'password1',
    salt        => 'longenoughsalt',
    t_cost      => 16,
    m_factor    => "4M",
    parallelism => 1,
    tag_size    => 16,
);

my $crypt = $ppr->as_crypt;
my $rfc2307 = $ppr->as_rfc2307;

my $ppr = Authen::Passphrase->from_crypt($crypt);
my $ppr = Authen::Passphrase->from_rfc2307($rfc2307);

=head1 DESCRIPTION

This modules allows L<Authen::Passphrase> compatible modules to use the
Argon2 key derivation function, which is the most secure one available
at this time (spring 2018).
The Argon2id variant is used via the L<Crypt::Argon2> module.

=head1 METHODS

=head2 new

See L</SYNOPSIS>.

=cut

1;
