# OhPHP

Write-up author: [Jade](https://jade.fyi)

This challenge is a reversing challenge written in PHP.

When you download the file, you realize it's complete garbage which is
technically executable as PHP:

```php
<?php
((('['^','^'.'^''.(('['^':').(']'^'?').('['^'('))((('['^'(').(')'^']').('['^')').('['^'(').(')'^']').('['^')'))('','.'))).('^'^''.(('['^':').(']'^'?').('['^'('))((('['^'(').(')'^']').('['^')').('['^'(').(')'^']').('['^')'))('','.')))
```

```
crewctf/ohphp » php chall.php


       ((((((        ^^^                              ^^^        ))))))     
     ((::::::(      ^:::^                            ^:::^      )::::::))   
   ((:::::::(      ^:::::^                          ^:::::^      ):::::::)) 
  (:::::::((      ^:::::::^                        ^:::::::^      )):::::::)
  (::::::(       ^:::::::::^                      ^:::::::::^       )::::::)
  (:::::(       ^:::::^:::::^                    ^:::::^:::::^       ):::::)
  (:::::(      ^:::::^ ^:::::^                  ^:::::^ ^:::::^      ):::::)
  (:::::(     ^^^^^^^   ^^^^^^^                ^^^^^^^   ^^^^^^^     ):::::)
  (:::::(                                                            ):::::)
  (:::::(                                                            ):::::)
  (:::::(                                                            ):::::)
  (::::::(                                                          )::::::)
  (:::::::((                                                      )):::::::)
   ((:::::::(                   ......  ......                   ):::::::)) 
     ((::::::(                  .::::.  .::::.                  )::::::)    
       ((((((                   ......  ......                   ))))))     


Flag: nya
Nope!
```

So I guess it's time to do something about this.

## Attempts at dynamic analysis

My first approach was to try to trace it with xdebug, but this didn't achieve
much, mostly because it is simply a billion calls to `strstr()` and `abs()`.
However, this is probably a useful technique to try first, so I shall document
how:

```
$ cp /etc/php/php.ini .
$ cat >> php.ini <<EOF
zend_extension=xdebug
[xdebug]
xdebug.collect_return = true
xdebug.collect_assignments = true
xdebug.start_with_request = true
xdebug.output_dir = .
xdebug.use_compression = false
EOF
$ XDEBUG_MODE=trace php -c php.ini chall.php
```

This will dump a file `./trace.*.xt` in the current directory, with a trace of
all the functions executed in the PHP script.

My next attempt to dynamically analyze it was to compile a copy of PHP and run
the challenge in `rr` then dump all the string concatenations since I saw lots
of those. Besides me getting hosed by `zsh` not expanding `$var` into multiple
arguments if I don't put `${=var}`, the building PHP part was not so hard.

I ran the program in `rr` and got a debugger:

```
$ XDEBUG_MODE=trace rr record -- php -c php.ini chall.php
$ rr replay
```

To dump the concatenations I did this trick to insert a print breakpoint:

```
(rr) dprintf Zend/zend_operators.c:2090,"\"%s\" . \"%s\" = %s\n",op1.value.str.val,op2.value.str.val,result_str.val
(rr) cont
```

However, again, I really did not get much of interest. Back to the drawing
board, I suppose.

## Static analysis

Looking at the code, there are a whole bunch of XORs of static strings. It
would be *at least* really useful to do a pass of constant evaluation over the
script to knock out all the most noisy parts of the obfuscation.

I contemplated writing some terrible program to do this, but this is really a
programming languages problem, so it has a programming languages solution: I
googled "PHP parser" and got <https://github.com/nikic/PHP-Parser>.

Looks like a PHP parser to me! Reading the docs briefly, I found it also has
constant evaluation support and some other nice stuff.

So:

```
$ composer require nikic/PHP-Parser
```

Let's write a script that just naively tries evaluating all the exprs in the
file and if successful, replace them:

<details>
<summary>PHP fixer code</summary>

```php
<?php
include(__DIR__ . '/vendor/autoload.php');

use PhpParser\BuilderHelpers;
use PhpParser\ConstExprEvaluationException;
use PhpParser\ConstExprEvaluator;
use PhpParser\Node;
use PhpParser\NodeDumper;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;

$parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP7);
$ast = $parser->parse(file_get_contents($argv[1]));
$dumper = new NodeDumper;

$evaluator = new ConstExprEvaluator();

class Visitor extends NodeVisitorAbstract {
    public function leaveNode(Node $node): Node {
        global $evaluator;
        global $dumper;

        if ($node instanceof Node\Expr) {
            try {
                $evald = $evaluator->evaluateSilently($node);
                return BuilderHelpers::normalizeValue($evald);
            } catch (ConstExprEvaluationException $e) {
                // echo "err: $e";
            }
        }

        return $node;
    }
}

$traverser = new NodeTraverser;
$traverser->addVisitor(new Visitor());

$newAst = $traverser->traverse($ast);
$pp = new PhpParser\PrettyPrinter\Standard();
$s = $pp->prettyPrintFile($newAst);
file_put_contents($argv[2], $s);
```

</details>

Run it:

```
$ php tidy.php chall.php chall1.php
```

Well that looks promising! But there's some unevaluated bits, in particular,
some junk with `abs` and `strstr` that we saw in the trace.

```php
<?php

(('Y' ^ '' . ('abs')(('strstr')('', '.'))) . ('^' ^ '' . ('abs')(('strstr')('', '.'))) . '_' . 'a' . 'r' . 'r' . 'a' . ('I' ^ '' . ('abs')(('strstr')('', '.'))))(('c' . ('_' ^ '' . ('abs' ......
```

However, these calls are all using constants, so we can just write some more
code to evaluate them in our `Visitor`:

```php
<?php
// ...
        if ($node instanceof Node\Expr\FuncCall) {
            try {
                $name = ($node->name instanceof Node\Expr) ? $evaluator->evaluateSilently($node->name) : $node->name;
                switch ($name) {
                    case 'abs':
                        $arg = $evaluator->evaluateSilently($node->getArgs()[0]->value);
                        return BuilderHelpers::normalizeValue(abs($arg));
                    case 'strstr':
                        $a1 = $evaluator->evaluateSilently($node->getArgs()[0]->value);
                        $a2 = $evaluator->evaluateSilently($node->getArgs()[1]->value);
                        return BuilderHelpers::normalizeValue(strstr($a1, $a2));
                }

                // Fix ('printf')('blah') -> printf('blah')
                $node->name = new Node\Name($name);
                // echo $dumper->dump($node) . '\n';
                return $node;
            } catch (ConstExprEvaluationException $e) {}
        }
```

With that, we get code that is merely shit, rather than completely unusable:

```php
<?php

in_array(count(get_included_files()), array('1')) ? strcmp(php_sapi_name(), 'cli') ? printf('Use php-cli to run the challenge!
') : printf(gzinflate(base64_decode('1dTBDYAgDAXQe6fgaC8O4DDdfwyhVGmhbaKe/BfQfF8gAQFKz8aRh0JEJY0qIIenINTBEY3qNNVUAfuXzIGitJVqpiBa4yp2U8ZKtKmANzewbaqG2lrAGbNWslOvgD52lULNLfgY9ZiZtdxCsLJ3+Q/2RVuOxji0jyl9aJfrZLJzxhgtS65TWS66wdr7fYzRFtvc/wU9Wpn6BQGc'))) . define('F', readline('Flag: ')) . (strcmp(strlen(constant('F')), '41') ? printf('Nope!
') : (in_array(substr(constant('F'), '0', '5'), array('crew{')) ? ('strstr')(strrev(crc32(substr(constant('F'), '5', '4'))), '7607349263') ? strnatcmp('A/k', substr(constant('F'), '5', '4') ^ substr(constant('F'), '9', '4')) ? printf('Nope xor!
')
// ...
```

With some cleanup and clarifying error messages, this is the full challenge code:

<details>
<summary>Full challenge code</summary>

```php
<?php

function p($v) {
    var_dump($v);
    return $v;
}

in_array(count(get_included_files()), array('1')) ? strcmp(php_sapi_name(), 'cli') ? printf("Use php-cli to run the challenge!\n") : printf(gzinflate(base64_decode('1dTBDYAgDAXQe6fgaC8O4DDdfwyhVGmhbaKe/BfQfF8gAQFKz8aRh0JEJY0qIIenINTBEY3qNNVUAfuXzIGitJVqpiBa4yp2U8ZKtKmANzewbaqG2lrAGbNWslOvgD52lULNLfgY9ZiZtdxCsLJ3+Q/2RVuOxji0jyl9aJfrZLJzxhgtS65TWS66wdr7fYzRFtvc/wU9Wpn6BQGc'))) . define('F', readline('Flag: ')) .

(strcmp(strlen(constant('F')), '41')
? printf("Nope 1!\n")
: (in_array(substr(constant('F'), '0', '5'), array('crew{'))
    ? strstr(strrev(crc32(substr(constant('F'), '5', '4'))), '7607349263')
        ? strnatcmp("A\x1b/k", substr(constant('F'), '5', '4') ^ substr(constant('F'), '9', '4'))
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
```

</details>

## Solving the challenge

The first condition on the flag is that it is 41 bytes long, so, into
`test.php` goes:

```php
<?php
define('F', 'crew{abcdefghijklmnopqrstuvwxyz123456789}');
```

### First 4 bytes

We need to match some CRC. This kind of thing could probably be brute forced
since it is just 4 bytes, but that would take writing some Rust to get it done
expediently. However, CRC32 is a very-non-cryptographically-secure algorithm
that's mostly twiddling bits and has a constant number of loop iterations,
which means it is perfect fodder for a SAT solver.

The conditions we need to meet are:
* Produces a CRC that, when reversed, is a substring of `7607349263`
* The data must be ASCII since it is a flag

I used z3 because it's easy, so off to Google for "z3 python crc" and neat,
[someone wrote the code already][z3-code]. Cool, so I don't have to do the hard
part :D

[z3-code]: https://gist.github.com/percontation/11310679

Let's attack these one by one.

The reversed CRC must be a substring of `7607349263`. This is equivalent to the
more convenient problem "the CRC is a substring of `3629437067`", so we thus
have a list of acceptable CRCs which we can encode as `Or(crc == a, crc == b,
crc == c, crc == d, ...)` as a constraint to z3:

```python
from itertools import combinations
crc = z3crc32(data)
revd = '3629437067'
# This combinations code nicked off the internet as well
subs = [int(revd[x:y]) for x, y in combinations(range(len(revd) + 1), r = 2)]
s.add(Or(*[crc == s for s in subs]))
```

Conveniently, whoever wrote this example code was probably solving a CTF so
they already did the ASCII part. I had to fix up the script to work properly in
Python 3, but after that, we got the first part of the flag, which seems legit:

```
$ python flagify.py
sat
[data = 1885892703]
b'php_'
```

<details>
<summary>Full Python z3 script</summary>

```python
from z3 import *
from itertools import combinations
import codecs

# https://gist.github.com/percontation/11310679

def z3crc32(data, crc=0):
    crc ^= 0xFFFFFFFF
    for c in data:
        for block in range(24, -1, -8):
            crc ^= LShR(c, block) & 0xFF
            for i in range(8):
                crc = If(crc & 1 == BitVecVal(1, 32),
                         LShR(crc, 1) ^ 0xedb88320, LShR(crc, 1))
    return crc ^ 0xFFFFFFFF


s = Solver()
data = [BitVec('data', 32)]

# Returns a z3 expression that is true iff the input BitVec32 as a 4-byte string is all ascii.
def isAscii(bv):
    # Note the use of z3.And here. Using python's `and` would be incorrect!
    return And(32 <= (LShR(bv, 0) & 0xff), (LShR(bv, 0) & 0xff) < 127, 32
               <= (LShR(bv, 8) & 0xff), (LShR(bv, 8) & 0xff) < 127, 32
               <= (LShR(bv, 16) & 0xff), (LShR(bv, 16) & 0xff) < 127, 32
               <= (LShR(bv, 24) & 0xff), (LShR(bv, 24) & 0xff) < 127)


for d in data:
    s.add(isAscii(d))

crc = z3crc32(data)
revd = '3629437067'
subs = [int(revd[x:y]) for x, y in combinations(range(len(revd) + 1), r = 2)]
s.add(Or(*[crc == s for s in subs]))

print(s.check())
m = s.model()
print(m)

def intToText(x):
    return str(codecs.decode(hex(x)[2:].strip('L').ljust(8,'0'), 'hex'))

s = ''
for d in data:
    s += intToText(m.eval(d).as_long())

print(s)
```

</details>

### 4 bytes of xor

The next 4 bytes have to match this:

```php
<?php
strnatcmp("A\x1b/k", substr(constant('F'), '5', '4') ^ substr(constant('F'), '9', '4'))
```

However, we *know* the substring of length 4 starting at 5: it's `php_`! So we
can just do:

```php
<?php
echo "[9:13] = " . ("A\x1b/k" ^ substr(constant('F'), '5', '4')) . "\n";
```

Which is: `1s_4`.

### Several bytes of AES

The next code to deal with is this:

```php
<?php
srand('31337')
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
```

This is an AES decryption using a *mostly* known key:

We know that it is `crew{php_1s_4ijk`, where `ijk` are unknown bytes. That's a
key space of 2^24, which is trivial to just brute force. Here's some PHP to
print all the candidate strings that are ascii if we try all the values for
the 24 bytes of the key we don't know:

```php
<?php

for ($a = 0; $a <= 255; $a += 1) {
    echo "a: $a\n";
    for ($b = 0; $b <= 255; $b += 1) {
        for ($c = 0; $c <= 255; $c += 1) {
            $key[13] = chr($a);
            $key[14] = chr($b);
            $key[15] = chr($c);

            $decd = openssl_decrypt('wCX3NcMho0BZO0SxG2kHxA==', 'aes-128-cbc', $key, '2', $iv);

            if (ctype_print($decd)) {
                echo "candidate $a $b $c: $decd\n";
            }
        }
    }
}
```

I actually did it in Rust because I assumed I was too impatient to wait for
2^24 loop iterations (turns out this was like 1 minute at most, but my Rust
took 1.5s).

```
candidate? ? È ~ "@<*@m|ot8B$/BkGI"
candidate? _ l 4 "ngu4ge_0f_m4g1c_"
candidate? k ÷  "IT?_!tPh.4[Q2yB)"
candidate? ô * "8Ml\\\"z-H8*n~[=a\\"
candidate? ¿ b Ï "-(P*.)jQ+L,uU-RM"
```

Most of these are nonsense, but `_l4nguage_0f_m4g1c` sure sounds like flag
bits. I wasted a little time here by transscribing the previous parts of the
flag wrong (d'oh! dyslexia strikes again), which led me to rewrite this
cracking in PHP and notice the mistake.

The second bit with `in_array` is a very obtuse way of writing
`ctype_print(constant('D')) && strpos(substr(constant('F'), 15, 17),
constant('D'))`. This will pass if we put the stuff we just got into the flag.

So far we have: `crew{php_1s_4_l4ngu4ge_0f_m4g1c_23456789}`

### SHA256 and more XOR

Next up, this stuff:

```php
<?php
strcmp(
    base64_encode(hash('sha256', substr(constant('F'), '0', '32'))
                    ^ substr(constant('F'), '32')
    ),
    'BwdRVwUHBQVF')
```

Or, rephrased more tersely: `base64enc(sha256(F[0:32]) ^ F[32:]) ==
'BwdRVwUHBQVF'`. We know `F[0:32]` and thus `sha256(F[0:32])`, so we can
rearrange to find `F[32:]`:
`F[32:] = sha256(F[0:32]) ^ base64dec('BwdRVwUHBQVF')`.

```php
<?php
echo "last substr: " . substr(constant('F'), '32') . "\n";
echo "decoded: " . (hash('sha256', substr(constant('F'), '0', '32')) ^ base64_decode('BwdRVwUHBQVF')) . "\n";
```

And:

```
last substr: 5b0e7b6a}
decoded: 5b0e7b6a}
```

So our flag is: `crew{php_1s_4_l4ngu4ge_0f_m4g1c_5b0e7b6a}`

## What did I learn?

I was kind of reticent to choose to approach the static analysis of the thing
as a compilers problem (since I think I overestimated the complexity of the
obfuscation) and wasted a bunch of time trying to dynamically analyze it. The
obfuscation yielded very quickly once I sicced it at a simple interpreter, and
I'm glad I used this software-engineering approach of using compiler tooling
rather than putting on my CTF player hat and trying to bodge something with
regexes or suchlike, since it was plain faster to do it properly.

The idea of throwing it into xdebug was a good one, but going further was
probably not worth the suffering of compiling a custom build of PHP to try to
trace more stuff.

Dealing with 2^24 iterations of a sufficiently simple loop in a dynamic
language is *not* that bad, and I should have just tried writing it in PHP
first. Recently I did a CryptoCTF problem of some funny encryption algorithm
with 2^32 possibilities and I chose to translate it into Rust and brute force
it instead of bothering to analyze it much; that one I don't think would have
been possible to just brute force in Python.
