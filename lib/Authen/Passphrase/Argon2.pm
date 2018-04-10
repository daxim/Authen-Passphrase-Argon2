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

1;

__END__

=encoding UTF-8

=head1 SYNOPSIS

    use Authen::Passphrase::Argon2 qw();
    use Crypt::URandom qw(urandom);

    # hash a passphrase
    my $ppr = Authen::Passphrase::Argon2->new(
        passphrase  => 'burro clang natty stave flake latest',
        salt        => urandom(16),
        t_cost      => 3,
        m_factor    => '4096M',
        parallelism => 4,
        tag_size    => 16,
    );

    # store one of these hashes in a database
    my $crypt = $ppr->as_crypt;
    my $rfc2307 = $ppr->as_rfc2307;

    # later, when the user attempts to log in again,
    # retrieve the hash and verify the supplied passphrase against it
    my $ppr = Authen::Passphrase->from_crypt($crypt);
    my $ppr = Authen::Passphrase->from_rfc2307($rfc2307);
    $ppr->match($login_attempt_passphrase);

=head1 DESCRIPTION

This modules allows L<Authen::Passphrase> compatible modules to use the
Argon2 key derivation function, which is the most secure one available
at this time (spring 2018).
The Argon2id variant is used via the L<Crypt::Argon2> module.

=head1 METHODS

=head2 new

Takes a list of key/value pairs. The keys are L</passphrase>, L</salt>,
L</t_cost>, L</m_factor>, L</parallelism>, L</tag_size>.

See L<https://password-hashing.net/argon2-specs.pdf> §6.4, §8, §9 (2015)
and L<https://tools.ietf.org/html/draft-irtf-cfrg-argon2#section-4> §4 (2018).

Security is a process, not a product. Review the parameters every year, migrate
hashes to increased parameters to keep up with the growth in hardware power.
L<https://security.stackexchange.com/> L<https://crypto.stackexchange.com/>
L<https://www.keylength.com/>

=head3 passphrase

Reject passwords or passphrases that are known:
L<http://pwnedpasswords.com/Passwords>
L<https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange>

Encourage your users to make secure, memorable passphrases by using Diceware
or similar. L<https://en.wikipedia.org/wiki/Diceware> The synopsis shows an
example.

Six words from the Diceware dictionary amount to only 77.5 bits of entropy,
which falls short of the required key size for good security. The key
stretching in Argon2 compensates for that.
L<https://ruudvanasseldonk.com/2012/07/07/passphrase-entropy>

=head3 salt

Use 16 random octets. Avoid userspace random number generators.
L<https://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/>
L<Crypt::URandom>, as shown in the synopsis, is fine.

The salt must be different for each generated hash.

=head3 t_cost

Pick the highest number so that calculating a hash does not exceed 0.5 seconds.
This follows the suggestion from the Argon2 documents above.

You balance frustrating the attacker against the usability of the whole log-in
process, including database access and networks roundtrips.

=head3 m_factor

Use the value C<4096M>, this follows the suggestion from the Argon2 documents
above. Decrease the amount of memory if necessary.

This distribution ships with a program F<authen-passphrase-argon2-benchmark.pl>
that assists you in finding good parameters for your hardware.

=head3 parallelism

This is the number of threads running. The recommendation from the Argon2 PDF
above is to count the number of CPU cores and double it, but that assumes that
"threads per core" is always 2, which is not universally true. Reality is quite
a bit more complicated: L<https://unix.stackexchange.com/a/279354>

In order to fully load the system, count the number of logical CPUs instead.
This is returned by the C<nproc> command or in Perl by C<_SC_NPROCESSORS_ONLN>
from L<POSIX::1003::Sysconf>.

=head3 tag_size

Use 16 (bytes), this follows the suggestion from the Argon2 documents above,
there expressed as 128 bits.
