#include "AES.h"
#include <string.h>
#include <stdio.h>

static void print(uint8_t *any, int len) {
    for (int i = 0; i < len; i++) {
        printf("%x ", any[i]);
    }
    printf("\n");
}

static void test_AES_gen_key(void) {
    uint8_t *key = AES_gen_key();
    print(key, AES_BLOCK_SIZE);
}

static void test_shift_rows() {
    uint8_t *state = AES_gen_key();
    shift_rows(state);
    print(state, AES_BLOCK_SIZE);
}

static void test_mix_cols() {
    uint8_t state[AES_BLOCK_SIZE] =  {
        0x57, 0x68, 0x61, 0x74,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
    };
    mix_cols(state);
    print(state, AES_BLOCK_SIZE);
}

void test_AES(void) {
    printf("------- test start -------\n");
    test_AES_gen_key();
    test_shift_rows();
    test_mix_cols();
    printf("------- test end ---------\n");
}