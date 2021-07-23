#include <stdint.h>

#ifndef IN_K3C_ORG_JRANDOM
#define IN_K3C_ORG_JRANDOM
#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t jrandom_t;

static inline void jrandom_init(jrandom_t* jrand, long seed) {
    *jrand = (seed ^ 0x5DEECE66DL) & ((1L << 48) - 1);
}

static inline int jrandom_next_int(jrandom_t* jrand, int bound) {
    *jrand = (*jrand * 0x5DEECE66DL + 0xBL) & ((1L << 48) - 1);

    if ((bound & -bound) == bound)
        return (int)((bound * (long)(*jrand >> (48-31))) >> 31);

    int bits, val;
    do {
        bits = *jrand >> (48-31);
        val = bits % bound;
    } while (bits - val + (bound-1) < 0);
    return val;
}

#ifdef __cplusplus
}
#endif
#endif