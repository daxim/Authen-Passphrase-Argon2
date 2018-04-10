use strict;
use warnings;

use Test::More;
BEGIN { use_ok('Authen::Passphrase::Argon2') }

my $x = Authen::Passphrase::Argon2->new( {
    passphrase  => 'password1',
    salt        => 'longenoughsalt',
    t_cost      => 16,
    m_factor    => "4M",
    parallelism => 1,
    tag_size    => 16,
} );

ok $x->match('password1'), 'match with correct password ok';
ok !$x->match('password2'), 'match with incorrect password fails';

is $x->as_crypt,
    '$argon2id$v=19$m=4096,t=16,p=1$bG9uZ2Vub3VnaHNhbHQ$5zFJ2PN5Lsk1GLvB3FrSyg',
    'as_crypt';
is $x->as_rfc2307,
    '{ARGON2}$argon2id$v=19$m=4096,t=16,p=1$bG9uZ2Vub3VnaHNhbHQ$5zFJ2PN5Lsk1GLvB3FrSyg',
    'as_rfc2307';

subtest 'from_crypt' => sub {
    ok my $y = Authen::Passphrase::Argon2->from_crypt(
        '$argon2id$v=19$m=4096,t=16,p=1$bG9uZ2Vub3VnaHNhbHQ$5zFJ2PN5Lsk1GLvB3FrSyg'
    ), 'from_crypt';

    is $y->m_factor,    4096, 'm_factor ok';
    is $y->t_cost,      16,   't_cost ok';
    is $y->parallelism, 1,    'parallelism ok';

    ok $y->match('password1'), 'match with correct password ok';
    ok !$y->match('password2'), 'match with incorrect password fails';
};

subtest 'from_rfc2307' => sub {
    ok my $y = Authen::Passphrase::Argon2->from_rfc2307(
        '{ARGON2}$argon2id$v=19$m=4096,t=16,p=1$bG9uZ2Vub3VnaHNhbHQ$5zFJ2PN5Lsk1GLvB3FrSyg'
    ), 'from_rfc2307';

    is $y->m_factor,    4096, 'm_factor ok';
    is $y->t_cost,      16,   't_cost ok';
    is $y->parallelism, 1,    'parallelism ok';

    ok $y->match('password1'), 'match with correct password ok';
    ok !$y->match('password2'), 'match with incorrect password fails';
};

done_testing;
