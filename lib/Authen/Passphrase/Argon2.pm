use strict;
use warnings;

package Authen::Passphrase::Argon2;

# ABSTRACT: Argon2 support for Authen::Passphrase

use parent qw( Authen::Passphrase Class::Accessor::Fast );
use Carp;
use Crypt::Argon2 qw( argon2id_pass argon2id_verify );

__PACKAGE__->mk_accessors(qw( _hash ));
__PACKAGE__->mk_ro_accessors(
    qw( salt t_cost m_factor parallelism tag_size
        passphrase )
);

sub new {
    my ( $class, @args ) = @_;
    my $self = $class->SUPER::new(@args);

    croak "passphrase not set"  unless defined $self->passphrase;
    croak "salt not set"        unless defined $self->salt;
    croak "t_cost not set"      unless defined $self->t_cost;
    croak "m_factor not set"    unless defined $self->m_factor;
    croak "parallelism not set" unless defined $self->parallelism;
    croak "tag_size not set"    unless defined $self->tag_size;

    my $hash = argon2id_pass(
        $self->passphrase, $self->salt,        $self->t_cost,
        $self->m_factor,   $self->parallelism, $self->tag_size
    );
    $self->_hash($hash);

    return $self;
}

sub from_crypt {
    my ( $class, $crypt ) = @_;

    croak "invalid Argon2 crypt format"
        unless $crypt =~ m/^\$argon2id\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$/;

    return $class->SUPER::new( {
        m_factor    => $1,
        t_cost      => $2,
        parallelism => $3,
        _hash       => $crypt,
    } );
}

sub from_rfc2307 {
    my ( $class, $rfc2307 ) = @_;
    croak "invalid Argon2 RFC2307 format"
        unless $rfc2307 =~ m/^{ARGON2}(.*)$/;

    return $class->from_crypt($1);
}

sub match {
    my ( $self, $passphrase ) = @_;
    return argon2id_verify( $self->_hash, $passphrase );
}

sub as_crypt {
    my $self = shift;
    return $self->_hash;
}

sub as_rfc2307 {
    my $self = shift;
    return '{ARGON2}' . $self->_hash;
}

=head1 SYNOPSIS

use Authen::Passphrase::Argus2;

# hash a password
my $ppr = Authen::Passphrase::Argon2->new({
    passphrase  => 'password1',
    salt        => 'longenoughsalt',
    t_cost      => 16,
    m_factor    => "4M",
    parallelism => 1,
    tag_size    => 16,
});

my $crypt = $ppr->as_crypt;
my $rfc2307 = $ppr->as_rfc2307;

my $ppr = Authen::Passphrase->from_crypt($crypt);
my $ppr = Authen::Passphrase->from_rfc2307($rfc2307);

=cut

1;
