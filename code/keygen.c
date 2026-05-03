#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <wmmintrin.h>  // For AES-NI
#include <linux/bpf.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <errno.h>
#include <time.h>
#include "keygen.h"

#define NUM_THREADS 8
#define U64_HEX_FMT "%016llx"
#define U64_HEX_VAL(x) (unsigned long long)(x)

static struct hashkey all_keys;  // Global storage for all keys
static int key_indices[TOTAL_KEYS];

__attribute__((constructor))
static void init_key_indices() {
    for (int i = 0; i < TOTAL_KEYS; i++)
        key_indices[i] = i;
}

typedef struct {
    unsigned char *state;
    unsigned char *keys_array;
    int start_index;
    int num_keys;
    __m128i aes_key_schedule[11];  // 11 rounds for AES-128
} ThreadData;

void xor_bytes(const unsigned char *a, const unsigned char *b, unsigned char *out, size_t len) {
    for (size_t i = 0; i < len; i++) out[i] = a[i] ^ b[i];
}

void aes128_key_expansion(const unsigned char *key, __m128i *key_schedule) {
    __m128i tmp1, tmp2;
    key_schedule[0] = _mm_loadu_si128((const __m128i *)key);

#define AES_KEY_EXP_STEP(idx, rcon)                        \
    tmp1 = key_schedule[idx - 1];                          \
    tmp2 = _mm_aeskeygenassist_si128(tmp1, rcon);          \
    tmp2 = _mm_shuffle_epi32(tmp2, _MM_SHUFFLE(3, 3, 3, 3)); \
    tmp1 = _mm_xor_si128(tmp1, _mm_slli_si128(tmp1, 4));   \
    tmp1 = _mm_xor_si128(tmp1, _mm_slli_si128(tmp1, 4));   \
    tmp1 = _mm_xor_si128(tmp1, _mm_slli_si128(tmp1, 4));   \
    key_schedule[idx] = _mm_xor_si128(tmp1, tmp2);

    AES_KEY_EXP_STEP(1, 0x01)
    AES_KEY_EXP_STEP(2, 0x02)
    AES_KEY_EXP_STEP(3, 0x04)
    AES_KEY_EXP_STEP(4, 0x08)
    AES_KEY_EXP_STEP(5, 0x10)
    AES_KEY_EXP_STEP(6, 0x20)
    AES_KEY_EXP_STEP(7, 0x40)
    AES_KEY_EXP_STEP(8, 0x80)
    AES_KEY_EXP_STEP(9, 0x1B)
    AES_KEY_EXP_STEP(10, 0x36)

#undef AES_KEY_EXP_STEP
}

void aes128_encrypt_block(const unsigned char *input, unsigned char *output, const __m128i *key_schedule) {
    __m128i m = _mm_loadu_si128((const __m128i *)input);
    m = _mm_xor_si128(m, key_schedule[0]);
    for (int i = 1; i < 10; i++)
        m = _mm_aesenc_si128(m, key_schedule[i]);
    m = _mm_aesenclast_si128(m, key_schedule[10]);
    _mm_storeu_si128((__m128i *)output, m);
}

void even_mansour_AESNI(const unsigned char *input, const unsigned char *key,
                        unsigned char *output, __m128i *key_schedule) {
    unsigned char encrypted[KEY_SIZE];
    aes128_encrypt_block(input, encrypted, key_schedule);
    xor_bytes(encrypted, input, output, KEY_SIZE);
}

void *generate_keys_thread(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char current_state[KEY_SIZE];
    memcpy(current_state, data->state, KEY_SIZE);

    for (int i = 0; i < data->num_keys; i++) {
        int index = data->start_index + i;
        unsigned char input[KEY_SIZE] = {0};
        memcpy(input, &index, sizeof(index));

        even_mansour_AESNI(input, current_state,
                           data->keys_array + (index * KEY_SIZE),
                           data->aes_key_schedule);

        memcpy(current_state, data->keys_array + (index * KEY_SIZE), KEY_SIZE);
    }

    return NULL;
}

void generate_keys(const unsigned char *initial_state, unsigned char *keys_array) {
    __m128i key_schedule[11];
    aes128_key_expansion(initial_state, key_schedule);

    #pragma omp simd
    for (int i = 0; i < TOTAL_KEYS; i++) {
        __m128i input = _mm_set_epi32(0, 0, 0, i);
        __m128i encrypted = _mm_aesenc_si128(input, key_schedule[0]);
        
        // Unrolled AES rounds
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[1]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[2]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[3]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[4]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[5]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[6]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[7]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[8]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[9]);
        encrypted = _mm_aesenclast_si128(encrypted, key_schedule[10]);
        
        _mm_storeu_si128((__m128i*)&keys_array[i*KEY_SIZE], _mm_xor_si128(encrypted, input));
    }
}

static void init_bpf_attr(union bpf_attr *attr, int map_fd, void *value) {
    static __u32 zero = 0;
    memset(attr, 0, sizeof(*attr));
    attr->map_fd = (__u32)map_fd;
    attr->key = (__u64)(unsigned long)&zero;
    attr->value = (__u64)(unsigned long)value;
    attr->flags = BPF_ANY;
}

__attribute__((visibility("default")))
int generate_keys_and_load(const unsigned char *initial_state, int map_fd) {
    struct timespec t1, t2, t3;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t1);

    // 1. Single-pass SIMD generation
    __m128i key_schedule[11];
    aes128_key_expansion(initial_state, key_schedule);

    // 2. Parallel generation directly into all_keys
    #pragma omp simd
    for (int i = 0; i < TOTAL_KEYS; i++) {
        __m128i input = _mm_set_epi32(0, 0, 0, i);
        __m128i encrypted = _mm_aesenc_si128(input, key_schedule[0]);
        
        // Unrolled AES rounds
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[1]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[2]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[3]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[4]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[5]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[6]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[7]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[8]);
        encrypted = _mm_aesenc_si128(encrypted, key_schedule[9]);
        encrypted = _mm_aesenclast_si128(encrypted, key_schedule[10]);
        
        _mm_store_si128((__m128i*)&all_keys.keys[i], _mm_xor_si128(encrypted, input));
    }

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t2);
   
    union bpf_attr attr;
    init_bpf_attr(&attr, map_fd, &all_keys);

    int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t3);

    double keygen_time = (t2.tv_sec - t1.tv_sec) * 1000.0 + (t2.tv_nsec - t1.tv_nsec) / 1e6;
    double mapload_time = (t3.tv_sec - t2.tv_sec) * 1000.0 + (t3.tv_nsec - t2.tv_nsec) / 1e6;
    // printf("[Timing] Keygen: %.3f ms | Map load: %.3f ms\n", keygen_time, mapload_time);
    
    if (ret < 0) {
        perror("bpf_map_update_elem failed");
        return -errno;
    }

    return ret;
}
// New function to load just a single sync key
__attribute__((visibility("default")))
int load_sync_key(const unsigned char *sync_key, int map_fd) {
    struct hashkey key_container = {0};  // Initialize all zeros
    struct timespec t1, t2, t3;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t1);
    // Copy the sync key to the 0 position in the array
    memcpy(&key_container.keys[0], sync_key, KEY_SIZE);
    union bpf_attr attr;
    init_bpf_attr(&attr, map_fd, &key_container);

    int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t2);
    if (ret < 0) {
        perror("Failed to update sync key");
        return -errno;
    }
    double synkeyload_time = (t2.tv_sec - t1.tv_sec) * 1000.0 + (t2.tv_nsec - t1.tv_nsec) / 1e6;
    // printf("[Timing] SynkeyMap load: %.3f ms\n", synkeyload_time);
    
    return 0;
}