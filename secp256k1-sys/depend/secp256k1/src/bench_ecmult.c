/***********************************************************************
 * Copyright (c) 2017 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/
#include <stdio.h>

#include "secp256k1.c"
#include "../include/secp256k1.h"

#include "util.h"
#include "hash_impl.h"
#include "field_impl.h"
#include "group_impl.h"
#include "scalar_impl.h"
#include "ecmult_impl.h"
#include "bench.h"

#define POINTS 32768

static void help(char **argv) {
    printf("Benchmark EC multiplication algorithms\n");
    printf("\n");
    printf("Usage: %s <help|pippenger_wnaf|strauss_wnaf|simple>\n", argv[0]);
    printf("The output shows the number of multiplied and summed points right after the\n");
    printf("function name. The letter 'g' indicates that one of the points is the generator.\n");
    printf("The benchmarks are divided by the number of points.\n");
    printf("\n");
    printf("default (ecmult_multi): picks pippenger_wnaf or strauss_wnaf depending on the\n");
    printf("                        batch size\n");
    printf("pippenger_wnaf:         for all batch sizes\n");
    printf("strauss_wnaf:           for all batch sizes\n");
    printf("simple:                 multiply and sum each point individually\n");
}

typedef struct {
    /* Setup once in advance */
    rustsecp256k1_v0_12_context* ctx;
    rustsecp256k1_v0_12_scratch_space* scratch;
    rustsecp256k1_v0_12_scalar* scalars;
    rustsecp256k1_v0_12_ge* pubkeys;
    rustsecp256k1_v0_12_gej* pubkeys_gej;
    rustsecp256k1_v0_12_scalar* seckeys;
    rustsecp256k1_v0_12_gej* expected_output;
    rustsecp256k1_v0_12_ecmult_multi_func ecmult_multi;

    /* Changes per benchmark */
    size_t count;
    int includes_g;

    /* Changes per benchmark iteration, used to pick different scalars and pubkeys
     * in each run. */
    size_t offset1;
    size_t offset2;

    /* Benchmark output. */
    rustsecp256k1_v0_12_gej* output;
} bench_data;

/* Hashes x into [0, POINTS) twice and store the result in offset1 and offset2. */
static void hash_into_offset(bench_data* data, size_t x) {
    data->offset1 = (x * 0x537b7f6f + 0x8f66a481) % POINTS;
    data->offset2 = (x * 0x7f6f537b + 0x6a1a8f49) % POINTS;
}

/* Check correctness of the benchmark by computing
 * sum(outputs) ?= (sum(scalars_gen) + sum(seckeys)*sum(scalars))*G */
static void bench_ecmult_teardown_helper(bench_data* data, size_t* seckey_offset, size_t* scalar_offset, size_t* scalar_gen_offset, int iters) {
    int i;
    rustsecp256k1_v0_12_gej sum_output, tmp;
    rustsecp256k1_v0_12_scalar sum_scalars;

    rustsecp256k1_v0_12_gej_set_infinity(&sum_output);
    rustsecp256k1_v0_12_scalar_set_int(&sum_scalars, 0);
    for (i = 0; i < iters; ++i) {
        rustsecp256k1_v0_12_gej_add_var(&sum_output, &sum_output, &data->output[i], NULL);
        if (scalar_gen_offset != NULL) {
            rustsecp256k1_v0_12_scalar_add(&sum_scalars, &sum_scalars, &data->scalars[(*scalar_gen_offset+i) % POINTS]);
        }
        if (seckey_offset != NULL) {
            rustsecp256k1_v0_12_scalar s = data->seckeys[(*seckey_offset+i) % POINTS];
            rustsecp256k1_v0_12_scalar_mul(&s, &s, &data->scalars[(*scalar_offset+i) % POINTS]);
            rustsecp256k1_v0_12_scalar_add(&sum_scalars, &sum_scalars, &s);
        }
    }
    rustsecp256k1_v0_12_ecmult_gen(&data->ctx->ecmult_gen_ctx, &tmp, &sum_scalars);
    CHECK(rustsecp256k1_v0_12_gej_eq_var(&tmp, &sum_output));
}

static void bench_ecmult_setup(void* arg) {
    bench_data* data = (bench_data*)arg;
    /* Re-randomize offset to ensure that we're using different scalars and
     * group elements in each run. */
    hash_into_offset(data, data->offset1);
}

static void bench_ecmult_gen(void* arg, int iters) {
    bench_data* data = (bench_data*)arg;
    int i;

    for (i = 0; i < iters; ++i) {
        rustsecp256k1_v0_12_ecmult_gen(&data->ctx->ecmult_gen_ctx, &data->output[i], &data->scalars[(data->offset1+i) % POINTS]);
    }
}

static void bench_ecmult_gen_teardown(void* arg, int iters) {
    bench_data* data = (bench_data*)arg;
    bench_ecmult_teardown_helper(data, NULL, NULL, &data->offset1, iters);
}

static void bench_ecmult_const(void* arg, int iters) {
    bench_data* data = (bench_data*)arg;
    int i;

    for (i = 0; i < iters; ++i) {
        rustsecp256k1_v0_12_ecmult_const(&data->output[i], &data->pubkeys[(data->offset1+i) % POINTS], &data->scalars[(data->offset2+i) % POINTS]);
    }
}

static void bench_ecmult_const_teardown(void* arg, int iters) {
    bench_data* data = (bench_data*)arg;
    bench_ecmult_teardown_helper(data, &data->offset1, &data->offset2, NULL, iters);
}

static void bench_ecmult_1p(void* arg, int iters) {
    bench_data* data = (bench_data*)arg;
    int i;

    for (i = 0; i < iters; ++i) {
        rustsecp256k1_v0_12_ecmult(&data->output[i], &data->pubkeys_gej[(data->offset1+i) % POINTS], &data->scalars[(data->offset2+i) % POINTS], NULL);
    }
}

static void bench_ecmult_1p_teardown(void* arg, int iters) {
    bench_data* data = (bench_data*)arg;
    bench_ecmult_teardown_helper(data, &data->offset1, &data->offset2, NULL, iters);
}

static void bench_ecmult_0p_g(void* arg, int iters) {
    bench_data* data = (bench_data*)arg;
    int i;

    for (i = 0; i < iters; ++i) {
        rustsecp256k1_v0_12_ecmult(&data->output[i], NULL, &rustsecp256k1_v0_12_scalar_zero, &data->scalars[(data->offset1+i) % POINTS]);
    }
}

static void bench_ecmult_0p_g_teardown(void* arg, int iters) {
    bench_data* data = (bench_data*)arg;
    bench_ecmult_teardown_helper(data, NULL, NULL, &data->offset1, iters);
}

static void bench_ecmult_1p_g(void* arg, int iters) {
    bench_data* data = (bench_data*)arg;
    int i;

    for (i = 0; i < iters/2; ++i) {
        rustsecp256k1_v0_12_ecmult(&data->output[i], &data->pubkeys_gej[(data->offset1+i) % POINTS], &data->scalars[(data->offset2+i) % POINTS], &data->scalars[(data->offset1+i) % POINTS]);
    }
}

static void bench_ecmult_1p_g_teardown(void* arg, int iters) {
    bench_data* data = (bench_data*)arg;
    bench_ecmult_teardown_helper(data, &data->offset1, &data->offset2, &data->offset1, iters/2);
}

static void run_ecmult_bench(bench_data* data, int iters) {
    char str[32];
    sprintf(str, "ecmult_gen");
    run_benchmark(str, bench_ecmult_gen, bench_ecmult_setup, bench_ecmult_gen_teardown, data, 10, iters);
    sprintf(str, "ecmult_const");
    run_benchmark(str, bench_ecmult_const, bench_ecmult_setup, bench_ecmult_const_teardown, data, 10, iters);
    /* ecmult with non generator point */
    sprintf(str, "ecmult_1p");
    run_benchmark(str, bench_ecmult_1p, bench_ecmult_setup, bench_ecmult_1p_teardown, data, 10, iters);
    /* ecmult with generator point */
    sprintf(str, "ecmult_0p_g");
    run_benchmark(str, bench_ecmult_0p_g, bench_ecmult_setup, bench_ecmult_0p_g_teardown, data, 10, iters);
    /* ecmult with generator and non-generator point. The reported time is per point. */
    sprintf(str, "ecmult_1p_g");
    run_benchmark(str, bench_ecmult_1p_g, bench_ecmult_setup, bench_ecmult_1p_g_teardown, data, 10, 2*iters);
}

static int bench_ecmult_multi_callback(rustsecp256k1_v0_12_scalar* sc, rustsecp256k1_v0_12_ge* ge, size_t idx, void* arg) {
    bench_data* data = (bench_data*)arg;
    if (data->includes_g) ++idx;
    if (idx == 0) {
        *sc = data->scalars[data->offset1];
        *ge = rustsecp256k1_v0_12_ge_const_g;
    } else {
        *sc = data->scalars[(data->offset1 + idx) % POINTS];
        *ge = data->pubkeys[(data->offset2 + idx - 1) % POINTS];
    }
    return 1;
}

static void bench_ecmult_multi(void* arg, int iters) {
    bench_data* data = (bench_data*)arg;

    int includes_g = data->includes_g;
    int iter;
    int count = data->count;
    iters = iters / data->count;

    for (iter = 0; iter < iters; ++iter) {
        data->ecmult_multi(&data->ctx->error_callback, data->scratch, &data->output[iter], data->includes_g ? &data->scalars[data->offset1] : NULL, bench_ecmult_multi_callback, arg, count - includes_g);
        data->offset1 = (data->offset1 + count) % POINTS;
        data->offset2 = (data->offset2 + count - 1) % POINTS;
    }
}

static void bench_ecmult_multi_setup(void* arg) {
    bench_data* data = (bench_data*)arg;
    hash_into_offset(data, data->count);
}

static void bench_ecmult_multi_teardown(void* arg, int iters) {
    bench_data* data = (bench_data*)arg;
    int iter;
    iters = iters / data->count;
    /* Verify the results in teardown, to avoid doing comparisons while benchmarking. */
    for (iter = 0; iter < iters; ++iter) {
        rustsecp256k1_v0_12_gej tmp;
        rustsecp256k1_v0_12_gej_add_var(&tmp, &data->output[iter], &data->expected_output[iter], NULL);
        CHECK(rustsecp256k1_v0_12_gej_is_infinity(&tmp));
    }
}

static void generate_scalar(uint32_t num, rustsecp256k1_v0_12_scalar* scalar) {
    rustsecp256k1_v0_12_sha256 sha256;
    unsigned char c[10] = {'e', 'c', 'm', 'u', 'l', 't', 0, 0, 0, 0};
    unsigned char buf[32];
    int overflow = 0;
    c[6] = num;
    c[7] = num >> 8;
    c[8] = num >> 16;
    c[9] = num >> 24;
    rustsecp256k1_v0_12_sha256_initialize(&sha256);
    rustsecp256k1_v0_12_sha256_write(&sha256, c, sizeof(c));
    rustsecp256k1_v0_12_sha256_finalize(&sha256, buf);
    rustsecp256k1_v0_12_scalar_set_b32(scalar, buf, &overflow);
    CHECK(!overflow);
}

static void run_ecmult_multi_bench(bench_data* data, size_t count, int includes_g, int num_iters) {
    char str[32];
    size_t iters = 1 + num_iters / count;
    size_t iter;

    data->count = count;
    data->includes_g = includes_g;

    /* Compute (the negation of) the expected results directly. */
    hash_into_offset(data, data->count);
    for (iter = 0; iter < iters; ++iter) {
        rustsecp256k1_v0_12_scalar tmp;
        rustsecp256k1_v0_12_scalar total = data->scalars[(data->offset1++) % POINTS];
        size_t i = 0;
        for (i = 0; i + 1 < count; ++i) {
            rustsecp256k1_v0_12_scalar_mul(&tmp, &data->seckeys[(data->offset2++) % POINTS], &data->scalars[(data->offset1++) % POINTS]);
            rustsecp256k1_v0_12_scalar_add(&total, &total, &tmp);
        }
        rustsecp256k1_v0_12_scalar_negate(&total, &total);
        rustsecp256k1_v0_12_ecmult(&data->expected_output[iter], NULL, &rustsecp256k1_v0_12_scalar_zero, &total);
    }

    /* Run the benchmark. */
    if (includes_g) {
        sprintf(str, "ecmult_multi_%ip_g", (int)count - 1);
    } else {
        sprintf(str, "ecmult_multi_%ip", (int)count);
    }
    run_benchmark(str, bench_ecmult_multi, bench_ecmult_multi_setup, bench_ecmult_multi_teardown, data, 10, count * iters);
}

int main(int argc, char **argv) {
    bench_data data;
    int i, p;
    size_t scratch_size;

    int iters = get_iters(10000);

    data.ecmult_multi = rustsecp256k1_v0_12_ecmult_multi_var;

    if (argc > 1) {
        if(have_flag(argc, argv, "-h")
           || have_flag(argc, argv, "--help")
           || have_flag(argc, argv, "help")) {
            help(argv);
            return 0;
        } else if(have_flag(argc, argv, "pippenger_wnaf")) {
            printf("Using pippenger_wnaf:\n");
            data.ecmult_multi = rustsecp256k1_v0_12_ecmult_pippenger_batch_single;
        } else if(have_flag(argc, argv, "strauss_wnaf")) {
            printf("Using strauss_wnaf:\n");
            data.ecmult_multi = rustsecp256k1_v0_12_ecmult_strauss_batch_single;
        } else if(have_flag(argc, argv, "simple")) {
            printf("Using simple algorithm:\n");
        } else {
            fprintf(stderr, "%s: unrecognized argument '%s'.\n\n", argv[0], argv[1]);
            help(argv);
            return 1;
        }
    }

    data.ctx = rustsecp256k1_v0_12_context_create(SECP256K1_CONTEXT_NONE);
    scratch_size = rustsecp256k1_v0_12_strauss_scratch_size(POINTS) + STRAUSS_SCRATCH_OBJECTS*16;
    if (!have_flag(argc, argv, "simple")) {
        data.scratch = rustsecp256k1_v0_12_scratch_space_create(data.ctx, scratch_size);
    } else {
        data.scratch = NULL;
    }

    /* Allocate stuff */
    data.scalars = malloc(sizeof(rustsecp256k1_v0_12_scalar) * POINTS);
    data.seckeys = malloc(sizeof(rustsecp256k1_v0_12_scalar) * POINTS);
    data.pubkeys = malloc(sizeof(rustsecp256k1_v0_12_ge) * POINTS);
    data.pubkeys_gej = malloc(sizeof(rustsecp256k1_v0_12_gej) * POINTS);
    data.expected_output = malloc(sizeof(rustsecp256k1_v0_12_gej) * (iters + 1));
    data.output = malloc(sizeof(rustsecp256k1_v0_12_gej) * (iters + 1));

    /* Generate a set of scalars, and private/public keypairs. */
    rustsecp256k1_v0_12_gej_set_ge(&data.pubkeys_gej[0], &rustsecp256k1_v0_12_ge_const_g);
    rustsecp256k1_v0_12_scalar_set_int(&data.seckeys[0], 1);
    for (i = 0; i < POINTS; ++i) {
        generate_scalar(i, &data.scalars[i]);
        if (i) {
            rustsecp256k1_v0_12_gej_double_var(&data.pubkeys_gej[i], &data.pubkeys_gej[i - 1], NULL);
            rustsecp256k1_v0_12_scalar_add(&data.seckeys[i], &data.seckeys[i - 1], &data.seckeys[i - 1]);
        }
    }
    rustsecp256k1_v0_12_ge_set_all_gej_var(data.pubkeys, data.pubkeys_gej, POINTS);


    print_output_table_header_row();
    /* Initialize offset1 and offset2 */
    hash_into_offset(&data, 0);
    run_ecmult_bench(&data, iters);

    for (i = 1; i <= 8; ++i) {
        run_ecmult_multi_bench(&data, i, 1, iters);
    }

    /* This is disabled with low count of iterations because the loop runs 77 times even with iters=1
    * and the higher it goes the longer the computation takes(more points)
    * So we don't run this benchmark with low iterations to prevent slow down */
     if (iters > 2) {
        for (p = 0; p <= 11; ++p) {
            for (i = 9; i <= 16; ++i) {
                run_ecmult_multi_bench(&data, i << p, 1, iters);
            }
        }
    }

    if (data.scratch != NULL) {
        rustsecp256k1_v0_12_scratch_space_destroy(data.ctx, data.scratch);
    }
    rustsecp256k1_v0_12_context_destroy(data.ctx);
    free(data.scalars);
    free(data.pubkeys);
    free(data.pubkeys_gej);
    free(data.seckeys);
    free(data.output);
    free(data.expected_output);

    return(0);
}
