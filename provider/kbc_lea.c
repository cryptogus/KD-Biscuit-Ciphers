/*
 * KBC provider - LEA 연결부
 *
 * KBC 라이브러리의 LEA 함수는 uint32_t 배열(리틀엔디언 워드)을 받는데,
 * OpenSSL 은 바이트 스트림을 넘긴다. 그 사이를 변환해 준다.
 */
#include <stdint.h>
#include <string.h>
#include "kbcprov.h"
#include "../src/lea/lea.h"

static void bytes_to_words(uint32_t *w, const unsigned char *b, size_t nwords)
{
    size_t i;

    for (i = 0; i < nwords; i++)
        w[i] = GETU32(b + 4 * i);
}

static void words_to_bytes(unsigned char *b, const uint32_t *w, size_t nwords)
{
    size_t i;

    for (i = 0; i < nwords; i++)
        PUTU32(b + 4 * i, w[i]);
}

#define DEFINE_LEA_BLOCK(bits, nkw)                                          \
    static void lea##bits##_enc_block(unsigned char *out,                    \
                                      const unsigned char *in,               \
                                      const unsigned char *key)              \
    {                                                                        \
        uint32_t pt[4], ct[4], k[nkw];                                       \
                                                                             \
        bytes_to_words(pt, in, 4);                                           \
        bytes_to_words(k, key, nkw);                                         \
        LEA##bits##_ENC(ct, pt, k);                                          \
        words_to_bytes(out, ct, 4);                                          \
    }                                                                        \
    static void lea##bits##_dec_block(unsigned char *out,                    \
                                      const unsigned char *in,               \
                                      const unsigned char *key)              \
    {                                                                        \
        uint32_t pt[4], ct[4], k[nkw];                                       \
                                                                             \
        bytes_to_words(ct, in, 4);                                           \
        bytes_to_words(k, key, nkw);                                         \
        LEA##bits##_DEC(pt, ct, k);                                          \
        words_to_bytes(out, pt, 4);                                          \
    }

DEFINE_LEA_BLOCK(128, 4)
DEFINE_LEA_BLOCK(192, 6)
DEFINE_LEA_BLOCK(256, 8)

/* IMPLEMENT_KBC_CIPHER(이름, 모드소문자, 모드대문자, 키비트, 블록, IV길이, enc, dec) */
IMPLEMENT_KBC_CIPHER(lea, ecb, ECB, 128, 16,  0, lea128_enc_block, lea128_dec_block);
IMPLEMENT_KBC_CIPHER(lea, cbc, CBC, 128, 16, 16, lea128_enc_block, lea128_dec_block);
IMPLEMENT_KBC_CIPHER(lea, ecb, ECB, 192, 16,  0, lea192_enc_block, lea192_dec_block);
IMPLEMENT_KBC_CIPHER(lea, cbc, CBC, 192, 16, 16, lea192_enc_block, lea192_dec_block);
IMPLEMENT_KBC_CIPHER(lea, ecb, ECB, 256, 16,  0, lea256_enc_block, lea256_dec_block);
IMPLEMENT_KBC_CIPHER(lea, cbc, CBC, 256, 16, 16, lea256_enc_block, lea256_dec_block);
