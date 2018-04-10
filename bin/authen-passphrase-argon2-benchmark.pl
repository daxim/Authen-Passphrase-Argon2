use Authen::Passphrase::Argon2 qw();
use Benchmark qw(timeit :hireswallclock);
require Time::HiRes;
use Crypt::URandom qw(urandom);
use POSIX::1003::Sysconf qw(_SC_NPROCESSORS_ONLN);

# PODNAME: authen-passphrase-argon2-benchmark.pl

my $duration = $ARGV[0] || 0.5;
my $t_cost = 1;
my $m_factor = 4096;

while () {
    my $t = timeit(1, sub {
        my $apa = Authen::Passphrase::Argon2->new(
            passphrase  => 'burro clang natty stave flake latest',
            salt        => urandom(16),
            t_cost      => $t_cost,
            m_factor    => $m_factor . 'M',
            parallelism => _SC_NPROCESSORS_ONLN,
            tag_size    => 32,
        );
    });
    my $seconds = $t->real;
    if ($seconds > $duration) {
        # <https://tools.ietf.org/html/draft-irtf-cfrg-argon2#section-4>
        # "If it exceeds x even for t = 1, reduce m accordingly."
        if (1 == $t_cost) {
            $m_factor = int($m_factor / 1.618); # phi
            redo;
        } else {
            last;
        }
    }
    printf "t_cost: %2d | m_factor: %4dM = %6.2fs\n",
        $t_cost, $m_factor, $seconds;
    $t_cost++;
}

__END__

=head1 NAME

authen-passphrase-argon2-benchmark.pl

=head1 SYNOPSIS

    perl authen-passphrase-argon2-benchmark.pl
    perl authen-passphrase-argon2-benchmark.pl duration

=head1 OPTIONS

=head2 duration

Real positive number indicating the time-span in seconds of the
desired duration. Default is C<0.5>.

=head1 DESCRIPTION

This program times long it takes to compute passphrase hash
with increasing cost parameters. It stops after a user-definable
duration is reached.

When even t_cost == 1 already takes too long, the program reduces
the amount of memory and tries again.

=head2 sample output

    > perl -Ilib bin/authen-passphrase-argon2-benchmark.pl 6
    t_cost:  1 | m_factor: 4096M =   1.56s
    t_cost:  2 | m_factor: 4096M =   2.66s
    t_cost:  3 | m_factor: 4096M =   3.75s
    t_cost:  4 | m_factor: 4096M =   4.85s
    t_cost:  5 | m_factor: 4096M =   5.93s

    > perl -Ilib bin/authen-passphrase-argon2-benchmark.pl
    t_cost:  1 | m_factor:  966M =   0.34s
