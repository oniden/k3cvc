#include <errno.h>

#include "k3cvc.h"

size_t k3cvc_init(struct k3cvc_ctx* ctx, long key, int max_rounds) {
    size_t buflen = 1;

    for(int i = 0; i < max_rounds+1; ++i)
        buflen += 8 << (i*3);
    ctx->max_rounds = max_rounds + 1;
    
    jrandom_init(&ctx->prng, key);
    return buflen;
}

void k3cvc_encrypt(struct k3cvc_ctx* ctx, char c, size_t *outoff, size_t *outlen) {
    ctx->buffer[0] = c;

    size_t inoff   = 0,
           inlen   = 1;
    size_t outlen_ = 8;
    int    rounds  = jrandom_next_int(&ctx->prng, ctx->max_rounds)+1;

    for(int n = 0; n < rounds; ++n) {
	    size_t outoff_ = inoff + inlen; // output is stored as adjacent to input.
	    
	    for(size_t i = 0; i < inlen; ++i)
		    for(size_t j = 0; j < 8; ++j)
		        ctx->buffer[i*8 + (7-j) + outoff_] = (ctx->buffer[i + inoff] >> j & 1) == 1 ? '\'' : '-';
	    
	    inoff    = outoff_; // slide to its encoded part.
	    inlen    = outlen_; // encoded parts length is made its length.
	    outlen_ *= 8;       // next output's length is 8x the encoded.
	}

    // because last output becomes the input for next OP.
    *outoff = inoff;
    *outlen = inlen;
}

size_t k3cvc_get_readsize(struct k3cvc_ctx* ctx) {
    ctx->dec_rounds = jrandom_next_int(&ctx->prng, ctx->max_rounds)+1;
    return 8 << (((size_t)ctx->dec_rounds-1)*3);
}

int k3cvc_decrypt(struct k3cvc_ctx* ctx, char *c) {
    size_t inoff  = 0,
	       inlen  = 8 << (((size_t)ctx->dec_rounds-1)*3);
	size_t outlen = inlen / 8;

    for(int n = 0; n < ctx->dec_rounds; ++n) {
	    size_t outoff = inoff + inlen;
	    
	    for(size_t i = 0; i < outlen; ++i) {
            ctx->buffer[i + outoff] = 0;
            
            for(size_t j = 0; j < 8; ++j) {
                char d = ctx->buffer[i*8 + (7-j) + inoff];
                if(d != '-' && d != '\'')
                    return EILSEQ;
                
                ctx->buffer[i + outoff] |= (d == '\'' ? 1 : 0) << j;
            }
	    }
	    
	    inoff  += inlen;  // slide to its decoded part.
	    inlen   = outlen; // decoded parts length is made its length.
	    outlen /= 8;      // next output's length is (1/8)x the decoded.
	}

    *c = ctx->buffer[inoff];
    return 0;
}
