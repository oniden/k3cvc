#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <argparse/argparse.h>
#include <libk3cvc/k3cvc.h>

static const char* description = "K3C Viol Cipher encrypt/decrypt-ing tool.";
static const char* epilogue    = "Data is read from STDIN and output to STDOUT.";

int main(int argc, const char** argv) {
    long pin;
    int max_rds = 3;
    int decode = 0;

    struct argparse argp;
    struct argparse_option argopts[] = {
        OPT_HELP(),
        OPT_INTEGER('r', NULL, &max_rds, "Maximum RVC rounds", NULL, 0, 0),
        OPT_BOOLEAN('d', NULL, &decode, "Decode the input", NULL, 0, 0),
        OPT_END()
    };

    argparse_init(&argp, argopts, &(const char*){"[-rd] PIN"}, 0);
    argparse_describe(&argp, description, epilogue);
    argc = argparse_parse(&argp, argc, argv);

    // parse the pin mandatorily.
    if(argc < 1)     
        argparse_usage(&argp), exit(EXIT_FAILURE);
    else
        pin = strtol(argv[0], NULL, 0);


    struct k3cvc_ctx ctx;

    ctx.buffer = malloc(k3cvc_init(&ctx, pin, max_rds));
    
    // NOTE: conditionals 'breaking' denote possible corruption.
    // TODO: output to stderr if that happens.

    if(!decode)       
        for(;;) {
            if((ctx.buffer[0] = getc(stdin)) == EOF)
                break;

            size_t outoff, outlen;
            k3cvc_encrypt(&ctx, &outoff, &outlen);

            if(fwrite(ctx.buffer + outoff, 1, outlen, stdout) != outlen)
                break;
        }
    else
        for(;;) {
            size_t blklen = k3cvc_get_readsize(&ctx);

            // TODO: figure out if concealment is benificial.
            if(fread(ctx.buffer, 1, blklen, stdin) != blklen)
                break;

            char c;
            if(k3cvc_decrypt(&ctx, &c) == EILSEQ)
                return;

            if(fputc(c, stdout) == EOF)
                break;
        }

    free(ctx.buffer);
}
