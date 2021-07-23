#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <argparse/argparse.h>
#include <libk3cvc/k3cvc.h>

static const char* description = "K3C Viol Cipher encrypt/decrypt-ing tool.";
static const char* epilogue    = 
    "Data is read from STDIN and output to STDOUT.\n"
    "PIN is a 48-bit integer to use as encryption key.";

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

    argparse_init(&argp, argopts, (const char*[]){"[-rd] PIN", NULL}, 0);
    argparse_describe(&argp, description, epilogue);
    argc = argparse_parse(&argp, argc, argv);

    // parse the pin mandatorily.
    if(argc < 1)
	    argparse_usage(&argp), exit(EXIT_FAILURE);
    else {
        pin = strtol(argv[0], NULL, 0);
        if(errno != 0 || pin == 0)
            fprintf(stderr, "fatal: invalid PIN syntax\n"), exit(EXIT_FAILURE);
    }

    struct k3cvc_ctx ctx;

    ctx.buffer = malloc(k3cvc_init(&ctx, pin, max_rds));

    // NOTE: conditionals 'breaking' denote possible corruption.
    // TODO: output to stderr if that happens.

    if(!decode)
        for(;;) {
            char c = getc(stdin);
            if(c == EOF)
                break;

            size_t outoff, outlen;
            k3cvc_encrypt(&ctx, c, &outoff, &outlen);

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
                break;

            if(fputc(c, stdout) == EOF)
                break;
        }

    free(ctx.buffer);
}