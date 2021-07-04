#include <stddef.h>

#include "jrand.h"

#ifndef IN_K3C_ORG_K3CVC
#define IN_K3C_ORG_K3CVC
#ifdef __cplusplus
extern "C" {
#endif

struct k3cvc_ctx {
    char*     buffer;
    int       max_rounds;
    jrandom_t prng;

    int dec_rounds; // (decrpytor) current number of rounds
};

/**
 * \brief Initialise the (en/de)cryption context.
 * 
 * \param key seed of the randomizer
 * \param max_rounds maximum amount of RVC rounds per char
 * 
 * \return least amount of memory required to work.
 */
size_t k3cvc_init(struct k3cvc_ctx* ctx, long key, int max_rounds);

/**
 * \brief Encrypt a single character and output to the given buffer
 *        in the k3cvc_set_buffer call.
 * 
 * \param c character to be encrypted
 * \param outoff offset of output data in buffer
 * \param outlen length of output data in buffer
 */
void k3cvc_encrypt(struct k3cvc_ctx* ctx, char c, size_t *outoff, size_t *outlen);

/**
 * \brief Calculate the size of data to read and put in buffer.
 */
size_t k3cvc_get_readsize(struct k3cvc_ctx* ctx);

/**
 * \brief Decrypt the violsequence put in buffer to a single character.
 * 
 * \param c storage of decrypted character
 * \return 0 if succeeds, EILSEQ if not.
 */
int k3cvc_decrypt(struct k3cvc_ctx* ctx, char *c);

#ifdef __cplusplus
}
#endif
#endif
