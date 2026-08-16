/*
 * KBC OpenSSL 3 provider - 공용 헤더
 *
 * provider 내부에서만 쓰이는 자료구조와, 알고리즘 하나를 통째로
 * 찍어내는 IMPLEMENT_KBC_CIPHER 매크로를 정의한다.
 */
#ifndef KBCPROV_H
# define KBCPROV_H

# include <stddef.h>
# include <openssl/core.h>
# include <openssl/core_dispatch.h>
# include <openssl/core_names.h>
# include <openssl/params.h>
# include <openssl/evp.h>

# define KBC_MAX_BLOCK_SIZE 16
# define KBC_MAX_KEY_SIZE   32

/* KBC 라이브러리의 블록 암호 한 블록 처리 함수를 바이트 단위로 감싼 형태 */
typedef void (*KBC_BLOCK_FN)(unsigned char *out, const unsigned char *in,
                             const unsigned char *key);

/* 알고리즘 하나를 서술하는 정적 메타데이터 (읽기 전용, 공유됨) */
typedef struct kbc_cipher_desc_st {
    const char   *name;
    size_t        keylen;      /* 바이트 */
    size_t        blocksize;   /* 바이트 */
    size_t        ivlen;       /* ECB면 0 */
    unsigned int  mode;        /* EVP_CIPH_ECB_MODE / EVP_CIPH_CBC_MODE */
    KBC_BLOCK_FN  encrypt_block;
    KBC_BLOCK_FN  decrypt_block;
} KBC_CIPHER_DESC;

/* EVP_CIPHER_CTX 하나당 하나씩 만들어지는 실행 상태 */
typedef struct kbc_cipher_ctx_st {
    const KBC_CIPHER_DESC *desc;
    void          *provctx;
    unsigned char  key[KBC_MAX_KEY_SIZE];
    unsigned char  iv[KBC_MAX_BLOCK_SIZE];    /* CBC 체이닝 상태 */
    unsigned char  buf[KBC_MAX_BLOCK_SIZE];   /* 블록 미만 잔여 데이터 */
    size_t         bufsz;
    unsigned int   enc;
    unsigned int   pad;                       /* PKCS#7 패딩 사용 여부 */
    int            key_set;
} KBC_CIPHER_CTX;

/* kbc_ciphercommon.c 의 모드 비의존 구현 */
void *kbc_cipher_newctx(void *provctx, const KBC_CIPHER_DESC *desc);
void  kbc_cipher_freectx(void *vctx);
void *kbc_cipher_dupctx(void *vctx);
int   kbc_cipher_encrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                              const unsigned char *iv, size_t ivlen,
                              const OSSL_PARAM params[]);
int   kbc_cipher_decrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                              const unsigned char *iv, size_t ivlen,
                              const OSSL_PARAM params[]);
int   kbc_cipher_update(void *vctx, unsigned char *out, size_t *outl,
                        size_t outsize, const unsigned char *in, size_t inl);
int   kbc_cipher_final(void *vctx, unsigned char *out, size_t *outl,
                       size_t outsize);
int   kbc_cipher_cipher(void *vctx, unsigned char *out, size_t *outl,
                        size_t outsize, const unsigned char *in, size_t inl);
int   kbc_cipher_get_params(OSSL_PARAM params[], const KBC_CIPHER_DESC *desc);
int   kbc_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[]);
int   kbc_cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
const OSSL_PARAM *kbc_cipher_gettable_params(void *provctx);
const OSSL_PARAM *kbc_cipher_gettable_ctx_params(void *cctx, void *provctx);
const OSSL_PARAM *kbc_cipher_settable_ctx_params(void *cctx, void *provctx);

/*
 * 알고리즘 하나에 필요한 desc + thunk 2개 + OSSL_DISPATCH 배열을 생성한다.
 * get_params 와 newctx 만 알고리즘마다 달라지고(desc를 주입해야 하므로),
 * 나머지는 ctx 안에 desc 포인터가 들어있으므로 공용 함수를 그대로 쓴다.
 */
# define IMPLEMENT_KBC_CIPHER(lc, mode_lc, MODE_UC, kbits, blk, ivl,        \
                              enc_fn, dec_fn)                               \
    static const KBC_CIPHER_DESC lc##_##kbits##_##mode_lc##_desc = {        \
        #lc "-" #kbits "-" #mode_lc, (kbits) / 8, (blk), (ivl),             \
        EVP_CIPH_##MODE_UC##_MODE, enc_fn, dec_fn                           \
    };                                                                      \
    static OSSL_FUNC_cipher_newctx_fn lc##_##kbits##_##mode_lc##_newctx;    \
    static void *lc##_##kbits##_##mode_lc##_newctx(void *provctx)           \
    {                                                                       \
        return kbc_cipher_newctx(provctx,                                   \
                                 &lc##_##kbits##_##mode_lc##_desc);         \
    }                                                                       \
    static OSSL_FUNC_cipher_get_params_fn                                   \
        lc##_##kbits##_##mode_lc##_get_params;                              \
    static int lc##_##kbits##_##mode_lc##_get_params(OSSL_PARAM params[])   \
    {                                                                       \
        return kbc_cipher_get_params(params,                                \
                                     &lc##_##kbits##_##mode_lc##_desc);     \
    }                                                                       \
    const OSSL_DISPATCH kbc_##lc##kbits##mode_lc##_functions[] = {          \
        { OSSL_FUNC_CIPHER_NEWCTX,                                          \
          (void (*)(void))lc##_##kbits##_##mode_lc##_newctx },              \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))kbc_cipher_freectx },   \
        { OSSL_FUNC_CIPHER_DUPCTX,  (void (*)(void))kbc_cipher_dupctx },    \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT,                                    \
          (void (*)(void))kbc_cipher_encrypt_init },                        \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT,                                    \
          (void (*)(void))kbc_cipher_decrypt_init },                        \
        { OSSL_FUNC_CIPHER_UPDATE,  (void (*)(void))kbc_cipher_update },    \
        { OSSL_FUNC_CIPHER_FINAL,   (void (*)(void))kbc_cipher_final },     \
        { OSSL_FUNC_CIPHER_CIPHER,  (void (*)(void))kbc_cipher_cipher },    \
        { OSSL_FUNC_CIPHER_GET_PARAMS,                                      \
          (void (*)(void))lc##_##kbits##_##mode_lc##_get_params },          \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                 \
          (void (*)(void))kbc_cipher_gettable_params },                     \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                  \
          (void (*)(void))kbc_cipher_get_ctx_params },                      \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                  \
          (void (*)(void))kbc_cipher_set_ctx_params },                      \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                             \
          (void (*)(void))kbc_cipher_gettable_ctx_params },                 \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                             \
          (void (*)(void))kbc_cipher_settable_ctx_params },                 \
        { 0, NULL }                                                         \
    }

/* kbc_lea.c 에서 만들어지는 dispatch 배열들 */
extern const OSSL_DISPATCH kbc_lea128ecb_functions[];
extern const OSSL_DISPATCH kbc_lea128cbc_functions[];
extern const OSSL_DISPATCH kbc_lea192ecb_functions[];
extern const OSSL_DISPATCH kbc_lea192cbc_functions[];
extern const OSSL_DISPATCH kbc_lea256ecb_functions[];
extern const OSSL_DISPATCH kbc_lea256cbc_functions[];

#endif /* KBCPROV_H */
