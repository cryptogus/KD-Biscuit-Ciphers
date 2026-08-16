/*
 * KBC provider - 블록 암호 공통 구현 (ECB / CBC, PKCS#7 패딩)
 *
 * provider 쪽 cipher 는 EVP 가 해주던 일을 직접 해야 한다:
 *   - 블록 미만 입력 버퍼링
 *   - 모드 체이닝(CBC의 IV 갱신)
 *   - 패딩 붙이고 떼기
 * EVP 는 이제 단순 중계자일 뿐이다.
 */
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "kbcprov.h"

static void xor_block(unsigned char *dst, const unsigned char *src, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        dst[i] ^= src[i];
}

/* 온전한 블록 nblk개를 모드에 맞춰 처리한다. in 과 out 은 겹쳐도 된다. */
static void kbc_do_blocks(KBC_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t nblk)
{
    const KBC_CIPHER_DESC *d = ctx->desc;
    size_t bsz = d->blocksize;
    unsigned char tmp[KBC_MAX_BLOCK_SIZE];

    while (nblk-- > 0) {
        if (d->mode == EVP_CIPH_ECB_MODE) {
            if (ctx->enc)
                d->encrypt_block(out, in, ctx->key);
            else
                d->decrypt_block(out, in, ctx->key);
        } else if (ctx->enc) {                    /* CBC 암호화 */
            memcpy(tmp, in, bsz);
            xor_block(tmp, ctx->iv, bsz);
            d->encrypt_block(out, tmp, ctx->key);
            memcpy(ctx->iv, out, bsz);            /* 다음 블록용 체이닝 값 */
        } else {                                  /* CBC 복호화 */
            memcpy(tmp, in, bsz);                 /* in==out 대비해 먼저 보관 */
            d->decrypt_block(out, in, ctx->key);
            xor_block(out, ctx->iv, bsz);
            memcpy(ctx->iv, tmp, bsz);
        }
        in += bsz;
        out += bsz;
    }
}

void *kbc_cipher_newctx(void *provctx, const KBC_CIPHER_DESC *desc)
{
    KBC_CIPHER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;
    ctx->desc = desc;
    ctx->provctx = provctx;
    ctx->pad = 1;                                 /* EVP 기본값과 동일 */
    return ctx;
}

void kbc_cipher_freectx(void *vctx)
{
    KBC_CIPHER_CTX *ctx = vctx;

    if (ctx == NULL)
        return;
    OPENSSL_cleanse(ctx, sizeof(*ctx));           /* 키를 메모리에 남기지 않는다 */
    OPENSSL_free(ctx);
}

void *kbc_cipher_dupctx(void *vctx)
{
    KBC_CIPHER_CTX *in = vctx;
    KBC_CIPHER_CTX *out;

    if (in == NULL)
        return NULL;
    out = OPENSSL_malloc(sizeof(*out));
    if (out == NULL)
        return NULL;
    *out = *in;
    return out;
}

static int kbc_cipher_init(KBC_CIPHER_CTX *ctx, const unsigned char *key,
                           size_t keylen, const unsigned char *iv, size_t ivlen,
                           const OSSL_PARAM params[], int enc)
{
    const KBC_CIPHER_DESC *d = ctx->desc;

    ctx->enc = enc ? 1 : 0;
    ctx->bufsz = 0;

    if (iv != NULL && d->ivlen > 0) {
        if (ivlen != d->ivlen) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        memcpy(ctx->iv, iv, ivlen);
    }
    if (key != NULL) {
        if (keylen != d->keylen) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        memcpy(ctx->key, key, keylen);
        ctx->key_set = 1;
    }
    return kbc_cipher_set_ctx_params(ctx, params);
}

int kbc_cipher_encrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                            const unsigned char *iv, size_t ivlen,
                            const OSSL_PARAM params[])
{
    return kbc_cipher_init(vctx, key, keylen, iv, ivlen, params, 1);
}

int kbc_cipher_decrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                            const unsigned char *iv, size_t ivlen,
                            const OSSL_PARAM params[])
{
    return kbc_cipher_init(vctx, key, keylen, iv, ivlen, params, 0);
}

int kbc_cipher_update(void *vctx, unsigned char *out, size_t *outl,
                      size_t outsize, const unsigned char *in, size_t inl)
{
    KBC_CIPHER_CTX *ctx = vctx;
    size_t bsz = ctx->desc->blocksize;
    size_t outlen = 0, nblk, rem;

    *outl = 0;
    if (!ctx->key_set) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }
    if (inl == 0)
        return 1;

    /* 1) 이전에 남겨둔 부분 블록을 먼저 채운다 */
    if (ctx->bufsz > 0) {
        size_t n = bsz - ctx->bufsz;

        if (n > inl)
            n = inl;
        memcpy(ctx->buf + ctx->bufsz, in, n);
        ctx->bufsz += n;
        in += n;
        inl -= n;
        if (ctx->bufsz < bsz)
            return 1;                             /* 아직 한 블록이 안 찼다 */
        /*
         * 복호화 + 패딩이면 "마지막 블록"은 final 에서 패딩을 떼야 하므로
         * 더 들어올 데이터가 없는 한 내보내지 않고 붙들고 있는다.
         */
        if (!ctx->enc && ctx->pad && inl == 0)
            return 1;
        if (outsize < bsz) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        kbc_do_blocks(ctx, out, ctx->buf, 1);
        ctx->bufsz = 0;
        out += bsz;
        outsize -= bsz;
        outlen += bsz;
    }

    /* 2) 온전한 블록들을 처리한다 */
    nblk = inl / bsz;
    rem = inl % bsz;
    if (!ctx->enc && ctx->pad && rem == 0 && nblk > 0) {
        nblk--;                                   /* 마지막 블록은 붙들어 둔다 */
        rem = bsz;
    }
    if (nblk > 0) {
        if (outsize < nblk * bsz) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        kbc_do_blocks(ctx, out, in, nblk);
        in += nblk * bsz;
        outlen += nblk * bsz;
    }

    /* 3) 남은 자투리는 다음 update / final 로 넘긴다 */
    if (rem > 0)
        memcpy(ctx->buf, in, rem);
    ctx->bufsz = rem;

    *outl = outlen;
    return 1;
}

int kbc_cipher_final(void *vctx, unsigned char *out, size_t *outl,
                     size_t outsize)
{
    KBC_CIPHER_CTX *ctx = vctx;
    size_t bsz = ctx->desc->blocksize;
    size_t i, padval;

    *outl = 0;
    if (!ctx->key_set) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (ctx->enc) {
        if (!ctx->pad) {
            if (ctx->bufsz != 0) {
                ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
                return 0;
            }
            return 1;
        }
        /* PKCS#7: 남은 바이트 수만큼 패딩. 딱 떨어지면 블록 하나를 통째로 붙인다 */
        padval = bsz - ctx->bufsz;
        for (i = ctx->bufsz; i < bsz; i++)
            ctx->buf[i] = (unsigned char)padval;
        if (outsize < bsz) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        kbc_do_blocks(ctx, out, ctx->buf, 1);
        ctx->bufsz = 0;
        *outl = bsz;
        return 1;
    }

    /* 복호화 */
    if (!ctx->pad) {
        if (ctx->bufsz != 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
            return 0;
        }
        return 1;
    }
    if (ctx->bufsz != bsz) {
        ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
        return 0;
    }
    kbc_do_blocks(ctx, ctx->buf, ctx->buf, 1);
    padval = ctx->buf[bsz - 1];
    if (padval == 0 || padval > bsz) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
        return 0;
    }
    for (i = bsz - padval; i < bsz; i++) {
        if (ctx->buf[i] != (unsigned char)padval) {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
            return 0;
        }
    }
    if (outsize < bsz - padval) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    memcpy(out, ctx->buf, bsz - padval);
    ctx->bufsz = 0;
    *outl = bsz - padval;
    return 1;
}

/* EVP_Cipher() 용 one-shot 경로: 패딩 없이 블록 단위 그대로 처리 */
int kbc_cipher_cipher(void *vctx, unsigned char *out, size_t *outl,
                      size_t outsize, const unsigned char *in, size_t inl)
{
    KBC_CIPHER_CTX *ctx = vctx;
    size_t bsz = ctx->desc->blocksize;

    *outl = 0;
    if (!ctx->key_set) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }
    if (inl % bsz != 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
        return 0;
    }
    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    kbc_do_blocks(ctx, out, in, inl / bsz);
    *outl = inl;
    return 1;
}

/*
 * 알고리즘 자체의 성질 (EVP_CIPHER_get_block_size 등이 여기로 온다).
 * ctx 없이도 답할 수 있어야 하므로 desc 만 보고 채운다.
 */
static const OSSL_PARAM kbc_cipher_known_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END
};

const OSSL_PARAM *kbc_cipher_gettable_params(void *provctx)
{
    (void)provctx;
    return kbc_cipher_known_gettable_params;
}

int kbc_cipher_get_params(OSSL_PARAM params[], const KBC_CIPHER_DESC *desc)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, desc->mode))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, desc->blocksize))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, desc->keylen))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, desc->ivlen))
        return 0;
    return 1;
}

/* 이쪽은 ctx 별 상태 (패딩 on/off, 현재 IV 등) */
static const OSSL_PARAM kbc_cipher_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_END
};

const OSSL_PARAM *kbc_cipher_gettable_ctx_params(void *cctx, void *provctx)
{
    (void)cctx; (void)provctx;
    return kbc_cipher_known_gettable_ctx_params;
}

int kbc_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    KBC_CIPHER_CTX *ctx = vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->desc->keylen))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->desc->ivlen))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->pad))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p == NULL)
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL && ctx->desc->ivlen > 0
        && !OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->desc->ivlen))
        return 0;
    return 1;
}

static const OSSL_PARAM kbc_cipher_known_settable_ctx_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_END
};

const OSSL_PARAM *kbc_cipher_settable_ctx_params(void *cctx, void *provctx)
{
    (void)cctx; (void)provctx;
    return kbc_cipher_known_settable_ctx_params;
}

int kbc_cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    KBC_CIPHER_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL) {
        unsigned int pad;

        if (!OSSL_PARAM_get_uint(p, &pad))
            return 0;
        ctx->pad = pad ? 1 : 0;
    }
    return 1;
}
