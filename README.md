The K3C Violcipher is a symmetric, stream cipher with multi-key encryption based off RVC (Recursive Violeur Coding). 

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

To use this coding algorithm in cipher, we initiate a PRNG of Java's standard library then query integers within [1..*max rounds*] bound.
Then foreach character we process it through `RVC(c, r)` where `c` = *current character*, `p` = *random round count corresponding to index of current char*
merge it with subsequent outputs.

Here's the trick, we keep no boundaries in the ciphertext. The eavesdropper has to know two parameters for sepearting these boundaries, one is the
*max rounds* and another is the *seed* of the PRNG else he'd do wrong reads thus decrypting invalid data.

## How to use

TODO
