<?php

define('F', 'crew{php_1s_4_l4ngu4ge_0f_m4g1c_5b0e7b6a}');
function p($v) {
    var_dump($v);
    return $v;
}
echo "16: " . substr(constant('F'), '0', '16') . "\n";
echo "15: " . substr(constant('F'), '15', '17') . "\n";
echo 'crc32: ' . crc32(p(substr(constant('F'), '5', '4'))) . "\n";
srand('31337');
// 5ba6655c0f8dbd670b55b47b7eceba29
$iv = pack('L*', rand(), rand(), rand(), rand());
echo bin2hex($iv) . "\n";

$key = substr(constant('F'), '0', '16');

// did it in rust because its 10x faster
// for ($a = 0; $a <= 255; $a += 1) {
//     echo "a: $a\n";
//     for ($b = 0; $b <= 255; $b += 1) {
//         for ($c = 0; $c <= 255; $c += 1) {
//             $key[13] = chr($a);
//             $key[14] = chr($b);
//             $key[15] = chr($c);
//
//             $decd = openssl_decrypt('wCX3NcMho0BZO0SxG2kHxA==', 'aes-128-cbc', $key, '2', $iv);
//
//             if (ctype_print($decd)) {
//                 echo "candidate: $decd\n";
//             }
//         }
//     }
// }
// define('D', openssl_decrypt('wCX3NcMho0BZO0SxG2kHxA==', 'aes-128-cbc', substr(constant('F'), '0', '16'), '2', pack('L*', rand(), rand(), rand(), rand())));


echo "last substr: " . substr(constant('F'), '32') . "\n";
echo "decoded: " . (hash('sha256', substr(constant('F'), '0', '32')) ^ base64_decode('BwdRVwUHBQVF')) . "\n";
// echo json_encode(constant('D'));
