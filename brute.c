// Original non-working mess fixed by alula
//
// The AES-NI code seems to be taken from https://gist.github.com/acapola/d5b940da024080dfaf5f
//
// DO NOT USE ORIGINAL MAKEFILE
// IT COMPILES WITHOUT OPTIMIZATIONS (THIS CODE ALSO REQUIRES SSE4.1)
//
// Compilation: (I recommend clang).
//   clang brute.c -o brute -O3 -Wall -lpthread -maes -march=native -msse2 -msse -msse4.1
// If you prefer gcc:
//   gcc brute.c -o brute -O3 -Wall -lpthread -maes -march=native -msse2 -msse -msse4.1
//
// Usage: ./brute [num_threads]

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <wmmintrin.h>
#include <smmintrin.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#define NUM_THREADS 8
#define ALIGN16 __attribute__((aligned(16)))

typedef struct thread_data
{
    int thread_id;
} thread_data;

typedef union key_data
{
    __m128i m;
    uint8_t c[16];
} key_data;

typedef struct key_schedule
{
    key_data keys[11];
} key_schedule;

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static inline __m128i aes_128_key_expansion(__m128i key, __m128i keygened)
{
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));

    return _mm_xor_si128(key, keygened);
}

static inline void aes128_load_key(key_schedule *key_schedule, key_data enc_key)
{
    key_schedule->keys[0].m = _mm_loadu_si128(&enc_key.m);
    key_schedule->keys[1].m = AES_128_key_exp(key_schedule->keys[0].m, 0x01);
    key_schedule->keys[2].m = AES_128_key_exp(key_schedule->keys[1].m, 0x02);
    key_schedule->keys[3].m = AES_128_key_exp(key_schedule->keys[2].m, 0x04);
    key_schedule->keys[4].m = AES_128_key_exp(key_schedule->keys[3].m, 0x08);
    key_schedule->keys[5].m = AES_128_key_exp(key_schedule->keys[4].m, 0x10);
    key_schedule->keys[6].m = AES_128_key_exp(key_schedule->keys[5].m, 0x20);
    key_schedule->keys[7].m = AES_128_key_exp(key_schedule->keys[6].m, 0x40);
    key_schedule->keys[8].m = AES_128_key_exp(key_schedule->keys[7].m, 0x80);
    key_schedule->keys[9].m = AES_128_key_exp(key_schedule->keys[8].m, 0x1B);
    key_schedule->keys[10].m = AES_128_key_exp(key_schedule->keys[9].m, 0x36);
}

static inline void aes128_enc(const key_schedule *key_schedule, key_data plainText, key_data *outCipherText)
{
    __m128i m = _mm_loadu_si128(&plainText.m);

    m = _mm_xor_si128(m, key_schedule->keys[0].m);
    m = _mm_aesenc_si128(m, key_schedule->keys[1].m);
    m = _mm_aesenc_si128(m, key_schedule->keys[2].m);
    m = _mm_aesenc_si128(m, key_schedule->keys[3].m);
    m = _mm_aesenc_si128(m, key_schedule->keys[4].m);
    m = _mm_aesenc_si128(m, key_schedule->keys[5].m);
    m = _mm_aesenc_si128(m, key_schedule->keys[6].m);
    m = _mm_aesenc_si128(m, key_schedule->keys[7].m);
    m = _mm_aesenc_si128(m, key_schedule->keys[8].m);
    m = _mm_aesenc_si128(m, key_schedule->keys[9].m);
    m = _mm_aesenclast_si128(m, key_schedule->keys[10].m);

    _mm_storeu_si128(&outCipherText->m, m);
}

static inline bool key_data_equal(key_data k1, key_data k2)
{
    __m128i v = _mm_cmpeq_epi8(k1.m, k2.m);
    return _mm_movemask_epi8(v) == 0xffff;
    // SSE2 version:
    // __m128i v = _mm_xor_si128(k1.m, k2.m);
    // return _mm_testz_si128(v, v);
}

void hexdump(const key_data *data)
{
    const uint8_t *d = data->c;
    printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
           d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
}

#define KEYS_COUNT 1024
void *crack_thread(void *threadarg)
{
    thread_data *my_data = (thread_data *)threadarg;

    printf("Thread ID: %d\n", my_data->thread_id);

    const key_data cipher = {.c = {0x8B, 0x66, 0x68, 0xC2, 0x7D, 0x22, 0x61, 0x05, 0xA9, 0x17, 0xD6, 0x61, 0x41, 0xBC, 0x7B, 0x67}};
    const key_data plain = {.c = {0xC4, 0x93, 0xE8, 0x4A, 0xAD, 0xD1, 0xC3, 0x03, 0x91, 0x3A, 0xBD, 0x57, 0xFE, 0x09, 0x79, 0x36}};
    key_schedule key_schedule;
    key_data computed_cipher;
    key_data enc_keys[KEYS_COUNT];
    int fd = open("/dev/urandom", O_RDONLY, 0);
    if (fd < 0)
    {
        printf("Error: unable to open /dev/urandom\n");
        pthread_exit(NULL);
        return NULL;
    }

    for (;;)
    {
        read(fd, enc_keys, sizeof(enc_keys));
        for (int i = 0; i < KEYS_COUNT; i++)
        {
            // printf("Trying key %d: \n", i);
            //hexdump(&enc_keys[i]);
            aes128_load_key(&key_schedule, enc_keys[i]);
            aes128_enc(&key_schedule, plain, &computed_cipher);

            if (key_data_equal(cipher, computed_cipher))
            {
                hexdump(&cipher);
                hexdump(&computed_cipher);
                printf("cipher match, key is\n");
                hexdump(&enc_keys[i]);
                goto end;
            }
        }
    }

end:
    close(fd);
    pthread_exit(NULL);
    return NULL;
}

int main(int argc, char *argv[])
{
    int num_threads = NUM_THREADS;

    if (argc > 1)
    {
        num_threads = atoi(argv[1]);
    }

    if (num_threads <= 0)
    {
        printf("Invalid number of threads.\n");
        return 1;
    }

    printf("Using %d threads\n", num_threads);

    pthread_t *threads = (pthread_t *)malloc(sizeof(pthread_t) * num_threads);
    thread_data *td = (thread_data *)malloc(sizeof(thread_data) * num_threads);

    for (int i = 0; i < num_threads; i++)
    {
        td[i].thread_id = i;

        int rc = pthread_create(&threads[i], NULL, crack_thread, (void *)&td[i]);

        if (rc)
        {
            printf("Error: unable to create thread %d\n", rc);
            exit(-1);
        }
    }

    pthread_exit(NULL);

    return 0;
}
