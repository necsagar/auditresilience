#ifndef KEYGEN_H
#define KEYGEN_H

#ifdef __cplusplus
extern "C" {
#endif

#define KEY_SIZE 16
// #define TOTAL_KEYS 65536
#define TOTAL_KEYS 262144UL
// New hashkey structure definition
struct hashkey {
    uint64_t keys[TOTAL_KEYS][2]; 
};

void generate_keys(const unsigned char *initial_state, unsigned char *keys_array);
int generate_keys_and_load(const unsigned char *initial_state, int map_fd);
int load_sync_key(const unsigned char *initial_state, int map_fd);
#ifdef __cplusplus
}
#endif
#endif
