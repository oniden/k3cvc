The K3CVC (K3C Viol Cipher) is a symmetric, stream, multi-key cipher based off RVC (Recursive Violeur Coding).

## The Technique

RVC is a technique to recursively encode a given data in the K3C violeur format until certain depths (*output length* = *data length* * 8^*depth*).
In layman terms, it takes the input data then viols it and then viols the violed data and does this thing several times and outputs it. This can be
expressed in Pseudo-haskell-like code,

```hs

-- Implications:
--    Each byte is assumed to be always 8-bit
--    Violeur data must only have  "-" or "'"
--    Violeur data is aligned to 8B boundary
-- NOTE: THIS IS NOT HASKELL!

RVC(Message, Rounds) -> Violeur

RVC m 1 = flatten (map (x -> map (i -> if (x >> i & 1) is 1 then "'" else "-", 7..0), m))
RVC m n = RVC (RVC (m, n-1), 1)

IRVC(Violeur, Rounds) -> Message

IRVC v 1 = map (x -> reduce(0, o,i -> o | (if x[i] is "-" then 0 else 1) << i, 7..0), chunk(v, 8))
IRVC v n = IRVC (IRVC(m, n-1), 1)
```

To use this coding algorithm in cipher, we initiate a PRNG same as Java's standard library then query integers within [1..*max rounds*] bound.
Then foreach character we process it through `RVC(c, r)` where `c` = *current character*, `p` = *random round count corresponding to index of current char*
merge it with subsequent outputs.

Here's the trick, we keep no boundaries in the ciphertext. The eavesdropper has to know two parameters for sepearting these boundaries, one is the
*max rounds* and another is the *seed* of the PRNG else he'd do wrong reads thus decrypting invalid data.

### How-to

Build this program and install it.
```sh
$ git clone https://github.com/oniden/k3cvc --depth=1
$ cmake -B k3cvc/build -DCMAKE_BUILD_TYPE=Release
$ cmake --build k3cvc/build

# now if you run a UNIX based system.
$ su
$ cp k3cvc/build/k3cvcfy /usr/local/bin/
```

When you run the program with no arguments or with `--help`
```
$ k3cvcfy --help
Usage: [-rd] PIN
K3C Viol Cipher encrypt/decrypt-ing tool.

    -h, --help    show this help message and exit
    -r=<int>      Maximum RVC rounds
    -d            Decode the input
Data is read from STDIN and output to STDOUT.
PIN is a 48-bit integer to use as encryption key
```

To encrypt
```sh
$ k3cvcfy 0xBAL < pod.txt > pod.viol
# output sizes get quite large, so you can compress the entropy.
$ zstd --format=gzip --ultra -22 pod.viol
```

To decrypt
```
$ k3cvcfy -d 0xBAL < pod.viol > pod.txt.2
```

It's highly recommended to use this in pair with a compressor algorithm like Brotli, ZSTD, Zopfli, etc.
