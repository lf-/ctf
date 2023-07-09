<?php

echo json_encode('A/k') . "\n";

function p($v) {
    var_dump($v);
    return $v;
}

in_array(count(get_included_files()), array('1')) ? strcmp(php_sapi_name(), 'cli') ? printf("Use php-cli to run the challenge!\n") : printf(gzinflate(base64_decode('1dTBDYAgDAXQe6fgaC8O4DDdfwyhVGmhbaKe/BfQfF8gAQFKz8aRh0JEJY0qIIenINTBEY3qNNVUAfuXzIGitJVqpiBa4yp2U8ZKtKmANzewbaqG2lrAGbNWslOvgD52lULNLfgY9ZiZtdxCsLJ3+Q/2RVuOxji0jyl9aJfrZLJzxhgtS65TWS66wdr7fYzRFtvc/wU9Wpn6BQGc'))) . define('F', readline('Flag: ')) .

(strcmp(strlen(constant('F')), '41')
? printf("Nope 1!\n")
: (in_array(substr(constant('F'), '0', '5'), array('crew{'))
    // F[5:9] == 'php_'
    ? strstr(strrev(crc32(substr(constant('F'), '5', '4'))), '7607349263')
        // F[9:13] == '1s_4'
        ? strnatcmp('A/k', substr(constant('F'), '5', '4') ^ substr(constant('F'), '9', '4'))
            ? printf("Nope xor!\n")
            : srand('31337')
            . define('D', openssl_decrypt(
                    data: 'wCX3NcMho0BZO0SxG2kHxA==',
                    cipher_algo: 'aes-128-cbc',
                    passphrase: substr(constant('F'), '0', '16'),
                    options: OPENSSL_ZERO_PADDING,
                    iv: pack('L*', rand(), rand(), rand(), rand())))
            . (in_array(
                p(array_sum([ctype_print(constant('D')), strpos(substr(constant('F'), '15', '17'), constant('D'))])),
                array('2')
            )
            ? strcmp(
                base64_encode(hash('sha256',
                    substr(constant('F'), '0', '32'))
                    ^ substr(constant('F'), '32')
                ),
                'BwdRVwUHBQVF')
                ? printf("Nope 2!\n")
                : printf("Congratulations, this is the right flag!\n")
            : printf("Nope z!\n"))
    : printf("Nope 3!\n")
        : printf("Nope 4!\n"))
) : printf("Nope 5!\n");
