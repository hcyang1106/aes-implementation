#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "AES.h"

uint8_t *AES_gen_key(void) {
    uint8_t *key = malloc(sizeof(uint8_t) * AES_BLOCK_SIZE);

    // init in random
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        *(key + i) = i + 1;
    }

    return key;
}

static void key_expand_core(uint8_t *in, uint8_t it) {
    // move lsb to msb, other bytes shift right one byte
    uint32_t *tmp = (uint32_t *)in; // be sure to 32 byte pointer first
    *tmp = ((*tmp & 0xFF) << 24) | (*tmp >> 8);

    for (int i = 0; i < 4; i++) {
        *(in + i) = sbox[*(in + i)];
    }

    *in ^= rcon[it];
}

// generate 10 new keys, 11 keys in total
uint8_t *AES_key_expand(uint8_t *key) {
    uint8_t *exp_keys = calloc(1, sizeof(uint8_t) * AES_BLOCK_SIZE * (AES_TOTAL_ROUNDS + 1));
    memcpy(exp_keys, key, AES_BLOCK_SIZE); // first 16 is original key

    int rcon_it = 1;
    int gen_bytes = AES_BLOCK_SIZE;
    uint8_t tmp[4];

    while (gen_bytes < AES_BLOCK_SIZE * (AES_TOTAL_ROUNDS + 1)) {
        for (int i = 0; i < 4; i++) {
            tmp[i] = exp_keys[(gen_bytes - 4) + i]; // latest generated 4 bytes
        }

        if (gen_bytes % AES_BLOCK_SIZE == 0) { // do key_expand_core every 16 bytes
            key_expand_core(tmp, rcon_it++);
        }

        for (int i = 0; i < 4; i++) {
            exp_keys[gen_bytes] = exp_keys[gen_bytes - AES_BLOCK_SIZE] ^ tmp[i];
            gen_bytes++;
        }
    }

    return exp_keys;
}

static void sub_bytes (uint8_t *state) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        int idx = state[i];
        uint8_t sub = sbox[idx];
        state[i] = sub;
    }
}

void shift_rows(uint8_t *state) {
    uint8_t tmp[AES_BLOCK_SIZE];

    for (int i = 0; i < AES_BLOCK_LEN; i++) {
        int start_idx = i;
        int end_idx = start_idx + AES_BLOCK_LEN * (AES_BLOCK_LEN - 1);

        for (int j = 0; j < AES_BLOCK_LEN; j++) {
            int curr_idx = start_idx + AES_BLOCK_LEN * j;
            tmp[curr_idx] = (curr_idx + AES_BLOCK_LEN * i <= end_idx)
                ? state[curr_idx + AES_BLOCK_LEN * i]
                : state[curr_idx + AES_BLOCK_LEN * i - AES_BLOCK_SIZE]; 
        }
    }

    for(int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] = tmp[i];
    }
}

void mix_cols(uint8_t *state) {
    uint8_t tmp[AES_BLOCK_SIZE];
    memset(tmp, 0, AES_BLOCK_SIZE);

    for (int i = 0; i < AES_BLOCK_LEN; i++) {
        int a[AES_BLOCK_LEN] = {state[0 + AES_BLOCK_LEN * i],
                                state[1 + AES_BLOCK_LEN * i],
                                state[2 + AES_BLOCK_LEN * i],
                                state[3 + AES_BLOCK_LEN * i]};   

        for (int j = 0; j < AES_BLOCK_LEN; j++) {
            int b[AES_BLOCK_LEN] = {galois_mult_mat[0 + j],
                                    galois_mult_mat[4 + j],
                                    galois_mult_mat[8 + j],
                                    galois_mult_mat[12 + j]};
                      
            for (int k = 0; k < AES_BLOCK_LEN; k++) { // dot product of a and b
                switch (b[k]) {
                    case 1:
                        tmp[i * AES_BLOCK_LEN + j] ^= a[k];
                        break;
                    case 2:
                        tmp[i * AES_BLOCK_LEN + j] ^= mult2[a[k]];
                        break;
                    case 3:
                        tmp[i * AES_BLOCK_LEN + j] ^= mult3[a[k]];
                        break;
                    default:
                        fprintf(stderr, "galois multiplication matrix contains an invalid value\n");
                        break;
                }
            }
        }
    }

    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] = tmp[i];
    }
}

static void add_round_key(uint8_t *key, uint8_t *state) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] ^= key[i];
    }
}

int AES_get_len(const char *msg) {
    return (strlen(msg) % 16 == 0) ? strlen(msg) : (strlen(msg) / 16 + 1) * 16;
}

uint8_t *AES_encrypt(uint8_t *exp_keys, const char *msg, int padded_len) {
    int orig_len = strlen(msg);
    uint8_t *padded_msg = calloc(1, sizeof(uint8_t) * padded_len);
    
    for (int i = 0; i < padded_len; i++) {
        if (i >= orig_len) {
            padded_msg[i] = 0;
            continue;
        }
        padded_msg[i] = msg[i];
    }
    
    uint8_t *p = padded_msg;
    uint8_t *padded_msg_end = padded_msg + padded_len;

    while (p < padded_msg_end) {
        uint8_t state[AES_BLOCK_SIZE];
        memcpy(state, p, AES_BLOCK_SIZE);

        add_round_key(exp_keys, state); // init round (not included in total rounds)
        
        int rounds = AES_TOTAL_ROUNDS - 1;
        for (int i = 0; i < rounds; i++) {
            sub_bytes(state);
            shift_rows(state);
            mix_cols(state);
            add_round_key(exp_keys + AES_BLOCK_SIZE * (i + 1), state);
        }

        // final round
        sub_bytes(state);
        shift_rows(state);
        add_round_key(exp_keys + AES_BLOCK_SIZE * AES_TOTAL_ROUNDS, state);

        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            p[i] = state[i];
        }

        p += AES_BLOCK_SIZE;
    }
    
    return padded_msg;
}