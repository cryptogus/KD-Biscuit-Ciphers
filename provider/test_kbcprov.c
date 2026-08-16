/*
 * KBC provider 동작 확인
 *
 * 1. provider 를 명시적으로 로드하고
 * 2. EVP_CIPHER_fetch() 로 LEA-128-ECB 를 꺼내
 * 3. KISA 표준 테스트 벡터와 대조한 뒤
 * 4. LEA-128-CBC 로 패딩까지 포함한 왕복(encrypt→decrypt)을 확인한다.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>

static int fails = 0;

static void check(const char *what, int ok)
{
    printf("%-45s %s\n", what, ok ? "OK" : "FAIL");
    if (!ok) {
        fails++;
        ERR_print_errors_fp(stderr);
    }
}

static void hexdump(const char *tag, const unsigned char *b, size_t n)
{
    size_t i;

    printf("  %-12s", tag);
    for (i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\n");
}

/* KISA LEA-128 테스트 벡터 */
static const unsigned char lea128_key[16] = {
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0
};
static const unsigned char lea128_pt[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const unsigned char lea128_ct[16] = {
    0x9f, 0xc8, 0x4e, 0x35, 0x28, 0xc6, 0xc6, 0x18,
    0x55, 0x32, 0xc7, 0xa7, 0x04, 0x64, 0x8b, 0xfd
};

static int test_ecb_kat(OSSL_LIB_CTX *libctx)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char out[64];
    int outl = 0, tmpl = 0, ok = 0;

    cipher = EVP_CIPHER_fetch(libctx, "LEA-128-ECB", "provider=kbc");
    check("EVP_CIPHER_fetch(LEA-128-ECB)", cipher != NULL);
    if (cipher == NULL)
        return 0;

    check("  block size == 16", EVP_CIPHER_get_block_size(cipher) == 16);
    check("  key length == 16", EVP_CIPHER_get_key_length(cipher) == 16);

    ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex2(ctx, cipher, lea128_key, NULL, NULL) == 1
        && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1
        && EVP_EncryptUpdate(ctx, out, &outl, lea128_pt, sizeof(lea128_pt)) == 1
        && EVP_EncryptFinal_ex(ctx, out + outl, &tmpl) == 1) {
        outl += tmpl;
        ok = (outl == 16 && memcmp(out, lea128_ct, 16) == 0);
    }
    check("ECB 암호문이 KISA 벡터와 일치", ok);
    hexdump("expected", lea128_ct, 16);
    hexdump("got", out, 16);

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
}

static int test_cbc_roundtrip(OSSL_LIB_CTX *libctx)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    /* 블록 배수가 아닌 길이 → PKCS#7 패딩이 붙어야 한다 */
    const char *msg = "Kookmin Block Cipher via OpenSSL provider!";
    unsigned char iv[16];
    unsigned char ct[128], pt[128];
    int ctl = 0, ptl = 0, tmpl = 0, ok = 0;
    size_t msglen = strlen(msg);

    memset(iv, 0xA5, sizeof(iv));

    cipher = EVP_CIPHER_fetch(libctx, "LEA-128-CBC", "provider=kbc");
    check("EVP_CIPHER_fetch(LEA-128-CBC)", cipher != NULL);
    if (cipher == NULL)
        return 0;

    ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex2(ctx, cipher, lea128_key, iv, NULL) == 1
        && EVP_EncryptUpdate(ctx, ct, &ctl,
                             (const unsigned char *)msg, (int)msglen) == 1
        && EVP_EncryptFinal_ex(ctx, ct + ctl, &tmpl) == 1) {
        ctl += tmpl;
    }
    /* 42바이트 → 48바이트(3블록)로 패딩되어야 한다 */
    check("CBC 암호문 길이가 패딩된 블록 배수", ctl == 48);
    hexdump("ciphertext", ct, (size_t)ctl);

    EVP_CIPHER_CTX_free(ctx);
    ctx = EVP_CIPHER_CTX_new();
    tmpl = 0;
    if (EVP_DecryptInit_ex2(ctx, cipher, lea128_key, iv, NULL) == 1
        && EVP_DecryptUpdate(ctx, pt, &ptl, ct, ctl) == 1
        && EVP_DecryptFinal_ex(ctx, pt + ptl, &tmpl) == 1) {
        ptl += tmpl;
        ok = ((size_t)ptl == msglen && memcmp(pt, msg, msglen) == 0);
    }
    check("CBC 복호화 결과가 원문과 일치", ok);
    printf("  decrypted   \"%.*s\"\n", ptl, pt);

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
}

int main(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *kbc = NULL, *deflt = NULL;

    /* 설치하지 않고 현재 디렉터리에서 로드한다 */
    if (!OSSL_PROVIDER_set_default_search_path(libctx, ".")) {
        fprintf(stderr, "search path 설정 실패\n");
        return 1;
    }
    deflt = OSSL_PROVIDER_load(libctx, "default");
    kbc = OSSL_PROVIDER_load(libctx, "kbcprov");
    check("OSSL_PROVIDER_load(kbcprov)", kbc != NULL);
    if (kbc == NULL) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    check("provider self-test", OSSL_PROVIDER_self_test(kbc) == 1);

    test_ecb_kat(libctx);
    test_cbc_roundtrip(libctx);

    OSSL_PROVIDER_unload(kbc);
    if (deflt != NULL)
        OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);

    printf("\n%s\n", fails == 0 ? "=== 전부 통과 ===" : "=== 실패 있음 ===");
    return fails == 0 ? 0 : 1;
}
