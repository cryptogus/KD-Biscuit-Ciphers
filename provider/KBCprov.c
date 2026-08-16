/*
 * KBC (Kookmin Block Cipher) OpenSSL 3 provider - 진입점
 *
 * 이 파일이 provider 의 뼈대다. 하는 일은 세 가지뿐이다.
 *   1. OSSL_provider_init()  : OpenSSL 이 .so 를 열고 호출하는 유일한 심볼.
 *                              provider 자신의 dispatch table 을 돌려준다.
 *   2. get_params()          : 이름/버전/상태 같은 provider 메타데이터 응답.
 *   3. query_operation()     : "cipher 구현 내놔" 요청에 OSSL_ALGORITHM 배열 응답.
 *
 * 실제 암호 구현은 kbc_ciphercommon.c / kbc_lea.c 에 있다.
 *
 * 참고:
 *   https://docs.openssl.org/3.0/man7/provider/
 *   https://docs.openssl.org/3.0/man7/provider-cipher/
 *   https://github.com/openssl/openssl/blob/master/README-PROVIDERS.md
 */
#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include "kbcprov.h"

#define KBCPROV_NAME    "KBC Provider"
#define KBCPROV_VERSION "0.1.0"

/* provider 전역 컨텍스트. 지금은 core 핸들만 들고 있으면 충분하다. */
typedef struct kbc_provctx_st {
    const OSSL_CORE_HANDLE *handle;
} KBC_PROVCTX;

/* ------------------------------------------------------------------ */
/* provider 파라미터                                                    */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM kbcprov_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME,        OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION,     OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO,   OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS,      OSSL_PARAM_INTEGER,  NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *kbcprov_gettable_params(void *provctx)
{
    (void)provctx;
    return kbcprov_param_types;
}

static int kbcprov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    (void)provctx;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KBCPROV_NAME))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KBCPROV_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KBCPROV_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))   /* 1 = 사용 가능 */
        return 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/* 알고리즘 목록                                                        */
/* ------------------------------------------------------------------ */

/*
 * 각 항목: { "이름:별칭:별칭", "속성 문자열", dispatch table, 설명 }
 * 속성 문자열의 provider=kbc 는 EVP_CIPHER_fetch() 에서 "provider=kbc" 로
 * 골라 쓸 수 있게 해 준다.
 */
#define KBC_PROPS "provider=kbc"

static const OSSL_ALGORITHM kbcprov_ciphers[] = {
    { "LEA-128-ECB:LEA128-ECB", KBC_PROPS, kbc_lea128ecb_functions,
      "KBC LEA-128 ECB" },
    { "LEA-128-CBC:LEA128-CBC", KBC_PROPS, kbc_lea128cbc_functions,
      "KBC LEA-128 CBC" },
    { "LEA-192-ECB:LEA192-ECB", KBC_PROPS, kbc_lea192ecb_functions,
      "KBC LEA-192 ECB" },
    { "LEA-192-CBC:LEA192-CBC", KBC_PROPS, kbc_lea192cbc_functions,
      "KBC LEA-192 CBC" },
    { "LEA-256-ECB:LEA256-ECB", KBC_PROPS, kbc_lea256ecb_functions,
      "KBC LEA-256 ECB" },
    { "LEA-256-CBC:LEA256-CBC", KBC_PROPS, kbc_lea256cbc_functions,
      "KBC LEA-256 CBC" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *kbcprov_query(void *provctx, int operation_id,
                                           int *no_cache)
{
    (void)provctx;
    *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return kbcprov_ciphers;
    /* 나중에 해시/서명 등을 추가하려면 여기에 case 를 늘리면 된다:
     * case OSSL_OP_DIGEST:    return kbcprov_digests;
     * case OSSL_OP_SIGNATURE: return kbcprov_signatures;
     */
    default:
        return NULL;
    }
}

/* ------------------------------------------------------------------ */
/* provider dispatch table 과 초기화                                    */
/* ------------------------------------------------------------------ */

static void kbcprov_teardown(void *provctx)
{
    OPENSSL_free(provctx);
}

static const OSSL_DISPATCH kbcprov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,        (void (*)(void))kbcprov_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))kbcprov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,      (void (*)(void))kbcprov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))kbcprov_query },
    { 0, NULL }
};

/*
 * OpenSSL 이 이 모듈에서 찾는 유일한 심볼.
 *   in       : core(libcrypto)가 제공하는 함수들 - 필요하면 여기서 꺼내 쓴다
 *   out      : 우리가 제공하는 함수들 - 반드시 채워서 돌려줘야 한다
 *   provctx  : 이후 모든 콜백에 그대로 전달될 우리 컨텍스트
 */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    KBC_PROVCTX *ctx;

    (void)in;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;
    ctx->handle = handle;

    *provctx = ctx;
    *out = kbcprov_dispatch_table;
    return 1;
}
