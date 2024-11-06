#include "AES.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "test.h"

static void print_msg(uint8_t *enc_msg, int len) {
    for (int i = 0; i < len; i++) {
        printf("%x ", *(enc_msg + i));
    }
    printf("\n");
}

int main (void) {
    test_AES();

    const char *msg = "Message to be encrypted with AES";

    // original 16 bytes key
    uint8_t *key = AES_gen_key();
    // 11 keys in total
    uint8_t *exp_keys = AES_key_expand(key);

    int padded_len = AES_get_len(msg);
    uint8_t *enc_msg = AES_encrypt(exp_keys, msg, padded_len);
    print_msg(enc_msg, padded_len);

    free(key);
    free(exp_keys);
    free(enc_msg);
}