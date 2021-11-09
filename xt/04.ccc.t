#!/usr/bin/perl
#spake2plus: https://www.potaroo.net/ietf/ids/draft-bar-cfrg-spake2plus-03.html
use strict;
use warnings;
use bigint;
use Smart::Comments;
use Test::More;

use lib '../lib';
use Crypt::SPAKE2Plus;
use Digest::CMAC;


my $spake2plus = Crypt::SPAKE2Plus->new(
    curve_name => 'prime256v1',
    mac=> sub {
        my ($key, $data) = @_;
        my $omac1 = Digest::CMAC->new($key);
        $omac1->add($data);
        return pack("H*", $omac1->hexdigest);
    },
);

### n:  $spake2plus->{curve_hr}->{n}->to_hex()
my $curve_hr = $spake2plus->{curve_hr};
my $curve = $spake2plus->{curve};
my $M_Point = $spake2plus->init_M_or_N('M', pack('H*', '04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20'));
my $M = $spake2plus->encode_ec_point($M_Point);
my $N_Point = $spake2plus->init_M_or_N('N', pack('H*', '04d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7'));
my $N = $spake2plus->encode_ec_point($N_Point);
my $P = $spake2plus->{P};
### P:  unpack('H*', $spake2plus->encode_ec_point($P))

my $A = '';
### $A
my $B = '';
### $B

my $pwd = 'pleaseletmein';
my $salt = 'yellowsubmarines';

my ($w0_bn, $w1_bn) = $spake2plus->calc_w0_w1(\&Crypt::SPAKE2Plus::bmod_w0_w1_alt, $pwd, $A, $B, $salt, 32768, 8, 1, 80);

# A, B: w0, w1, L = w1*P

my $w0 = $w0_bn->to_hex();
### $w0
is($w0, 'e433ab43428320b24fab82f915d1db114acd72f8a4bf4fbf3c712b94bcc2f013', 'w0');

my $w1   = $w1_bn->to_hex() ;
### $w1
is($w1, '44363d157f471221b1e75e596ff4714a712b9578301665d84ec17004952523a8', 'w1');

my $L_Point = $spake2plus->calc_L($w1_bn);
my $L = $spake2plus->encode_ec_point($L_Point);
### L: unpack('H*', $L)

# A : X = x*P + w0*M
my $x = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
my $x_bn    = Crypt::Perl::BigInt->from_hex($x);
### $x
my $X_Point = $spake2plus->A_calc_X($w0_bn, $x_bn);
my $X       = $spake2plus->encode_ec_point( $X_Point );
### X: unpack('H*', $X)
is($X_Point->get_x()->to_bigint()->to_hex(), 'f44555207a617fd90900dba5c8e6f81eddbd87590873a63b9057dda9f138dbc1', 'X.x');
is($X_Point->get_y()->to_bigint()->to_hex(), '6f453195f6452ce71d399052435952b89a10b927435574f5e3707eae031c40e0', 'X.y');

# B : Y = y*P + w0*N
my $y = 'f1e1d1c1b1a191817161514131211101f0e0d0c0b0a090807060504030201000';
my $y_bn    = Crypt::Perl::BigInt->from_hex($y);
### $y
my $Y_Point = $spake2plus->B_calc_Y($w0_bn, $y_bn);
my $Y       = $spake2plus->encode_ec_point( $Y_Point );
### Y: unpack('H*', $Y)
is($Y_Point->get_x()->to_bigint()->to_hex(), 'b6fdaf3f6949869d68f667108b75e4ce74847e8953d1e3c6aae21699e8027211', 'Y.x');
is($Y_Point->get_y()->to_bigint()->to_hex(), 'c2d9b2b2a906cc7ea7020715dec44e95659e3fc8994f635b95e7c9ea5c362cbe', 'Y.y');

# A: Z = h*x*(Y - w0*N), V = h*w1*(Y - w0*N)
my ($A_Calc_Z_Point, $A_Calc_V_Point) = $spake2plus->A_calc_ZV($w0_bn, $w1_bn, $x_bn, $Y_Point);
my $A_Calc_Z       = $spake2plus->encode_ec_point( $A_Calc_Z_Point );
### A calc Z: unpack('H*', $A_Calc_Z)
is($A_Calc_Z_Point->get_x()->to_bigint()->to_hex(), '89af176e8122e67c00dbcea089bc49935634132b1b226030d2b14f16b3e73351', 'Z.x');
is($A_Calc_Z_Point->get_y()->to_bigint()->to_hex(), 'c2254b1b62477fdc976379f5ae7c57c6ac2b31ef9a032c33e4677c5c3acbb1d3', 'Z.y');

my $A_Calc_V       = $spake2plus->encode_ec_point( $A_Calc_V_Point );
### A calc V: unpack('H*', $A_Calc_V)
is($A_Calc_V_Point->get_x()->to_bigint()->to_hex(), '2f229f13e1ebfb6442a67eebdafb23b2f6e656597384035a8a1e50ad95d24211', 'V.x');
is($A_Calc_V_Point->get_y()->to_bigint()->to_hex(), '339e90a669dd8a56fb2524fb6e6c784b89019c1130c2def98143fb46dcc507d2', 'V.y');

# B: Z = h*y*(X - w0*M), V = h*y*L
my ($B_Calc_Z_Point, $B_Calc_V_Point) = $spake2plus->B_calc_ZV($w0_bn, $L_Point, $y_bn, $X_Point);
my $B_Calc_Z       = $spake2plus->encode_ec_point( $B_Calc_Z_Point );
### B calc Z: unpack('H*', $B_Calc_Z)
my $B_Calc_V       = $spake2plus->encode_ec_point( $B_Calc_V_Point );
### B calc V: unpack('H*', $B_Calc_V)

is($A_Calc_Z, $B_Calc_Z, 'A and B, Z');
is($A_Calc_V, $B_Calc_V, 'A and B, V');

# A/B calc TT
my $TT = $spake2plus->generate_TT_alt($X_Point, $Y_Point, $A_Calc_Z_Point, $A_Calc_V_Point, $w0_bn);
### TT: unpack("H*", $TT)

#my ( $Ka, $Ke ) = $spake2plus->split_key( $TT_digest );
my ( $Ka, $Ke ) = $spake2plus->calc_Ka_and_Ke( $TT );
### Ka: unpack("H*", $Ka)
is(unpack("H*", $Ka), '381fc44894aedc0fd37257fdca763ee4', 'CK');
### Ke: unpack("H*", $Ke)
is(unpack("H*", $Ke), '9f695017ba5e1df74a1b8bbf27fe1e0d', 'SK');

my ( $KcA, $KcB ) = $spake2plus->calc_KcA_and_KcB($Ka, 32, pack('H*', '5b0201015c0401010100'));
### KcA: unpack("H*", $KcA)
is(unpack("H*", $KcA), 'ab667caeffe27505265d0f2026e146ea', 'K1');
### KcB: unpack("H*", $KcB)
is(unpack("H*", $KcB), 'af679bf88b734e1cb7cd0243fb21a589', 'K2');


### MacA = cmac(KcA, Y)
my $MacA = $spake2plus->A_calc_MacA($KcA, $Y);
### MacA: unpack("H*", $MacA)
is(unpack("H*", $MacA), '23d1a618ad3acbfd7a9bd19fd1737107', 'MacA - M2');

### MacB = cmac(KcB, X)
my $MacB = $spake2plus->B_calc_MacB($KcB, $X);
### MacB: unpack("H*", $MacB)
is(unpack("H*", $MacB), '110d49f8c5a896e11d4dde4c3b9704d2', 'MacB - M1');

my $M1 = $spake2plus->B_calc_MacB($KcA, $X);
### M1 = cmac(KcA, X): unpack("H*", $M1)
is(unpack("H*", $M1),'110d49f8c5a896e11d4dde4c3b9704d2', 'M1');

my $M2 = $spake2plus->A_calc_MacA($KcB, $Y);
### M2 = cmac(KcB, Y): unpack("H*", $M2)
is(unpack("H*", $M2),'23d1a618ad3acbfd7a9bd19fd1737107', 'M2');


done_testing;
