#ifndef CLI_ARGS_H
#define CLI_ARGS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vendor/ketopt.h"

static inline int cli_is_help(const char *arg) {
    return arg && (!strcmp(arg, "-h") || !strcmp(arg, "--help"));
}

static inline void cli_usage(FILE *out, const char *prog, const char *usage) {
    fprintf(out, "Usage: %s %s\n", prog, usage);
}

static inline void cli_usage_error(const char *prog, const char *usage, const char *msg) {
    fprintf(stderr, "error: %s\n", msg);
    cli_usage(stderr, prog, usage);
    exit(1);
}

static inline void cli_parse_error(const char *prog, const char *usage,
                                   int argc, char **argv, const ketopt_t *opt, int c) {
    const char *arg = (opt->ind > 0 && opt->ind - 1 < argc) ? argv[opt->ind - 1] : "option";
    if (c == ':') {
        fprintf(stderr, "error: missing value for %s\n", arg);
    } else {
        fprintf(stderr, "error: unknown option %s\n", arg);
    }
    cli_usage(stderr, prog, usage);
    exit(1);
}

#endif
