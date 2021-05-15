/*
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Based on: https://github.com/ejurgensen/pair_ap, modified by David Klopp
 */

#include "srp.h"

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

typedef union
{
    SHA_CTX sha;
    SHA256_CTX sha256;
    SHA512_CTX sha512;
} HashCTX;

typedef struct
{
    BIGNUM * N;
    BIGNUM * g;
} ng_constant;

typedef struct srp_user_s
{
    enum hash_alg alg;
    ng_constant *ng;
    
    BIGNUM * a;
    BIGNUM * A;
    BIGNUM * S;
    
    const unsigned char *bytes_A;
    int authenticated;
    
    char *username;
    unsigned char *password;
    int password_len;
    
    unsigned char M [SHA512_DIGEST_LENGTH];
    unsigned char H_AMK [SHA512_DIGEST_LENGTH];
    unsigned char session_key [2 * SHA512_DIGEST_LENGTH]; // See hash_session_key()
    int session_key_len;
} srp_user_t;

#define BIGNUM_new(bn)                  bn = BN_new()
#define BIGNUM_free(bn)                 BN_free(bn)
#define BIGNUM_num_bytes(bn)            BN_num_bytes(bn)
#define BIGNUM_is_zero(bn)              BN_is_zero(bn)
#define BIGNUM_bn2bin(bn, buf, len)     BN_bn2bin(bn, buf)
#define BIGNUM_bin2bn(bn, buf, len)     bn = BN_bin2bn(buf, len, 0)
#define BIGNUM_hex2bn(bn, buf)          BN_hex2bn(&bn, buf)
#define BIGNUM_random(bn, num_bits)     BN_rand(bn, num_bits, 0, 0)
#define BIGNUM_add(bn, a, b)            BN_add(bn, a, b)
#define BIGNUM_sub(bn, a, b)            BN_sub(bn, a, b)

__attribute__((unused)) static void BIGNUM_mul(BIGNUM * bn, BIGNUM * a, BIGNUM * b)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_mul(bn, a, b, ctx);
    BN_CTX_free(ctx);
}

__attribute__((unused)) static void BIGNUM_mod(BIGNUM * bn, BIGNUM * a, BIGNUM * b)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_mod(bn, a, b, ctx);
    BN_CTX_free(ctx);
}

__attribute__((unused)) static void BIGNUM_modexp(BIGNUM * bn, BIGNUM * y, BIGNUM * q, BIGNUM * p)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(bn, y, q, p, ctx);
    BN_CTX_free(ctx);
}

__attribute__((unused)) static void BIGNUM_modadd(BIGNUM * bn, BIGNUM * a, BIGNUM * b, BIGNUM * m)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_add(bn, a, b, m, ctx);
    BN_CTX_free(ctx);
}

/*----------------------------------------------------------------------------*/
int hash_init(enum hash_alg alg, HashCTX *c)
{
    switch (alg)
    {
        case HASH_SHA1  : return SHA1_Init(&c->sha);
        case HASH_SHA224: return SHA224_Init(&c->sha256);
        case HASH_SHA256: return SHA256_Init(&c->sha256);
        case HASH_SHA384: return SHA384_Init(&c->sha512);
        case HASH_SHA512: return SHA512_Init(&c->sha512);
        default: return -1;
    };
}

int hash_update(enum hash_alg alg, HashCTX *c, const void *data, size_t len)
{
    switch (alg)
    {
        case HASH_SHA1  : return SHA1_Update(&c->sha, data, len);
        case HASH_SHA224: return SHA224_Update(&c->sha256, data, len);
        case HASH_SHA256: return SHA256_Update(&c->sha256, data, len);
        case HASH_SHA384: return SHA384_Update(&c->sha512, data, len);
        case HASH_SHA512: return SHA512_Update(&c->sha512, data, len);
        default: return -1;
    };
}

int hash_final(enum hash_alg alg, HashCTX *c, unsigned char *md)
{
    switch (alg)
    {
        case HASH_SHA1  : return SHA1_Final(md, &c->sha);
        case HASH_SHA224: return SHA224_Final(md, &c->sha256);
        case HASH_SHA256: return SHA256_Final(md, &c->sha256);
        case HASH_SHA384: return SHA384_Final(md, &c->sha512);
        case HASH_SHA512: return SHA512_Final(md, &c->sha512);
        default: return -1;
    };
}

unsigned char * hash(enum hash_alg alg, const unsigned char *d, size_t n, unsigned char *md)
{
    switch (alg)
    {
        case HASH_SHA1  : return SHA1(d, n, md);
        case HASH_SHA224: return SHA224(d, n, md);
        case HASH_SHA256: return SHA256(d, n, md);
        case HASH_SHA384: return SHA384(d, n, md);
        case HASH_SHA512: return SHA512(d, n, md);
        default: return NULL;
    };
}

int hash_length(enum hash_alg alg)
{
    switch (alg)
    {
        case HASH_SHA1  : return SHA_DIGEST_LENGTH;
        case HASH_SHA224: return SHA224_DIGEST_LENGTH;
        case HASH_SHA256: return SHA256_DIGEST_LENGTH;
        case HASH_SHA384: return SHA384_DIGEST_LENGTH;
        case HASH_SHA512: return SHA512_DIGEST_LENGTH;
        default: return -1;
    };
}

void update_hash_n(enum hash_alg alg, HashCTX *ctx, const BIGNUM* n)
{
    unsigned long len = BIGNUM_num_bytes(n);
    unsigned char *n_bytes = malloc(len);
    
    BIGNUM_bn2bin(n, n_bytes, len);
    hash_update(alg, ctx, n_bytes, len);
    free(n_bytes);
}

void hash_num(enum hash_alg alg, const BIGNUM* n, unsigned char *dest)
{
    int nbytes = BIGNUM_num_bytes(n);
    unsigned char *bin = malloc(nbytes);
    
    BIGNUM_bn2bin(n, bin, nbytes);
    hash(alg, bin, nbytes, dest);
    free(bin);
}

int hash_ab(enum hash_alg alg, unsigned char *md, const unsigned char *m1, int m1_len, const unsigned char *m2,
            int m2_len)
{
    HashCTX ctx;
    hash_init(alg, &ctx);
    hash_update(alg, &ctx, m1, m1_len);
    hash_update(alg, &ctx, m2, m2_len);
    return hash_final(alg, &ctx, md);
}

BIGNUM* H_ns(enum hash_alg alg, const BIGNUM* n, const unsigned char *bytes, int len_bytes)
{
    BIGNUM* bn;
    unsigned char buff[SHA512_DIGEST_LENGTH];
    int len_n  = BIGNUM_num_bytes(n);
    int nbytes = len_n + len_bytes;
    unsigned char *bin = malloc(nbytes);
    
    BIGNUM_bn2bin(n, bin, len_n);
    memcpy(bin + len_n, bytes, len_bytes);
    hash(alg, bin, nbytes, buff);
    free(bin);
    BIGNUM_bin2bn(bn, buff, hash_length(alg));
    return bn;
}

BIGNUM * H_nn_pad(enum hash_alg alg, const BIGNUM *n1, const BIGNUM *n2)
{
    BIGNUM *bn;
    unsigned char *bin;
    unsigned char buff[SHA512_DIGEST_LENGTH];
    int len_n1 = BIGNUM_num_bytes(n1);
    int len_n2 = BIGNUM_num_bytes(n2);
    int nbytes = 2 * len_n1;
    
    if ((len_n2 < 1) || (len_n2 > len_n1)) return 0;
    
    bin = calloc(1, nbytes);
    
    BIGNUM_bn2bin(n1, bin, len_n1);
    BIGNUM_bn2bin(n2, bin + nbytes - len_n2, len_n2);
    hash(alg, bin, nbytes, buff);
    free(bin);
    BIGNUM_bin2bn(bn, buff, hash_length(alg));
    return bn;
}

static int hash_session_key(enum hash_alg alg, const BIGNUM *n, unsigned char *dest)
{
    int nbytes = BIGNUM_num_bytes(n);
    unsigned char *bin = malloc(nbytes);
    unsigned char fourbytes[4] = { 0 }; // Only God knows the reason for this, and perhaps some poor soul at Apple
    
    BIGNUM_bn2bin(n, bin, nbytes);
    
    hash_ab(alg, dest, bin, nbytes, fourbytes, sizeof(fourbytes));
    
    fourbytes[3] = 1; // Again, only ...
    
    hash_ab(alg, dest + hash_length(alg), bin, nbytes, fourbytes, sizeof(fourbytes));
    
    free(bin);
    
    return (2 * hash_length(alg));
}

/*----------------------------------------------------------------------------*/
typedef struct nghex_t
{
    const char *n_hex;
    const char *g_hex;
} nghex_s;

// We only need 2048 right now, but keep the array in case we want to add others later
// All constants here were pulled from Appendix A of RFC 5054
static struct nghex_t global_Ng_constants[] =
{
    { /* 2048 */
        "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4"
        "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60"
        "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF"
        "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907"
        "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861"
        "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB"
        "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
        "2"
    },
    {0,0} /* null sentinel */
};

static ng_constant * new_ng(srp_ngtype_t ng_type, const char *n_hex, const char *g_hex)
{
    ng_constant *ng = calloc(1, sizeof(ng_constant));
    
    if (ng_type != SRP_NG_CUSTOM)
    {
        n_hex = global_Ng_constants[ng_type].n_hex;
        g_hex = global_Ng_constants[ng_type].g_hex;
    }
    
    BIGNUM_hex2bn(ng->N, n_hex);
    BIGNUM_hex2bn(ng->g, g_hex);
    
    return ng;
}

static void free_ng(ng_constant *ng)
{
    if (!ng) return;
    
    BIGNUM_free(ng->N);
    BIGNUM_free(ng->g);
    free(ng);
}


/*----------------------------------------------------------------------------*/
struct srp_user_s *srp_user_new(enum hash_alg alg, srp_ngtype_t ng_type, const char *username,
                                const unsigned char *bytes_password, int len_password, const char *n_hex,
                                const char *g_hex)
{
    struct srp_user_s *user  = calloc(1, sizeof(struct srp_user_s));
    int ulen = strlen(username) + 1;
    
    if (!user) goto erexit;
    
    user->alg = alg;
    user->ng  = new_ng(ng_type, n_hex, g_hex);
    
    BIGNUM_new(user->a);
    BIGNUM_new(user->A);
    BIGNUM_new(user->S);
    
    if (!user->ng || !user->a || !user->A || !user->S) goto erexit;
    
    user->username = malloc(ulen);
    user->password = malloc(len_password);
    user->password_len = len_password;
    
    if (!user->username || !user->password) goto erexit;
    
    memcpy(user->username, username, ulen);
    memcpy(user->password, bytes_password, len_password);
    
    user->authenticated = 0;
    user->bytes_A = 0;
    
    return user;
    
erexit:
    if (!user) return NULL;
    
    BIGNUM_free(user->a);
    BIGNUM_free(user->A);
    BIGNUM_free(user->S);
    
    free(user->username);
    if (user->password)
    {
        memset(user->password, 0, user->password_len);
        free(user->password);
    }
    free(user);
    
    return NULL;
}

void srp_user_free(struct srp_user_s *user)
{
    if(!user) return;
    
    BIGNUM_free(user->a);
    BIGNUM_free(user->A);
    BIGNUM_free(user->S);
    
    free_ng(user->ng);
    
    memset(user->password, 0, user->password_len);
    
    free(user->username);
    free(user->password);
    free((char *)user->bytes_A);
    
    memset(user, 0, sizeof(*user));
    free(user);
}

int srp_user_is_authenticated(struct srp_user_s *user)
{
    return user->authenticated;
}

const unsigned char * srp_user_get_session_key(struct srp_user_s *user, int *key_length)
{
    if (key_length) *key_length = user->session_key_len;
    return user->session_key;
}


/*----------------------------------------------------------------------------*/
/**
 Calculate A.
 */
void srp_user_start_authentication(struct srp_user_s *user, const unsigned char **bytes_A, int *len_A)
{
    BIGNUM_random(user->a, 256);
    BIGNUM_modexp(user->A, user->ng->g, user->a, user->ng->N);
    
    *len_A = BIGNUM_num_bytes(user->A);
    *bytes_A = malloc(*len_A);
    
    if (!*bytes_A)
    {
        *len_A = 0;
        *bytes_A = 0;
        return;
    }
    
    BIGNUM_bn2bin(user->A, (unsigned char *) *bytes_A, *len_A);
    
    user->bytes_A = *bytes_A;
}

/*----------------------------------------------------------------------------*/

/**
 x = H(salt | H(username | ":" | password))
 */
static BIGNUM *calculate_x(enum hash_alg alg, const BIGNUM *salt, const char *username, const unsigned char *password,
                           int password_len)
{
    unsigned char ucp_hash[SHA512_DIGEST_LENGTH];
    HashCTX ctx;
    
    hash_init(alg, &ctx);
    hash_update(alg, &ctx, username, strlen(username));
    hash_update(alg, &ctx, ":", 1);
    hash_update(alg, &ctx, password, password_len);
    hash_final(alg, &ctx, ucp_hash);
    
    return H_ns(alg, salt, ucp_hash, hash_length(alg));
}

/**
 I := username
 s := salt
 A := pkA
 B := pkB
 K := session_key (or secret)
 
 M = H(H(N) XOR H(g) | H(I) | s | A | B | K)
 */
static void calculate_M(enum hash_alg alg, ng_constant *ng, unsigned char *dest, const char *I, const BIGNUM * s,
                        const BIGNUM * A, const BIGNUM * B, const unsigned char *K, int K_len)
{
    unsigned char H_N[SHA512_DIGEST_LENGTH], H_g[SHA512_DIGEST_LENGTH], H_I[SHA512_DIGEST_LENGTH];
    unsigned char H_xor[SHA512_DIGEST_LENGTH];
    int i = 0, hash_len = hash_length(alg);
    HashCTX ctx;
    
    hash_num(alg, ng->N, H_N);
    hash_num(alg, ng->g, H_g);
    
    hash(alg, (const unsigned char *)I, strlen(I), H_I);
    
    for (i=0; i < hash_len; i++ ) H_xor[i] = H_N[i] ^ H_g[i];
    
    hash_init(alg, &ctx);
    
    hash_update(alg, &ctx, H_xor, hash_len);
    hash_update(alg, &ctx, H_I,   hash_len);
    update_hash_n(alg, &ctx, s);
    update_hash_n(alg, &ctx, A);
    update_hash_n(alg, &ctx, B);
    hash_update(alg, &ctx, K, K_len);
    
    hash_final(alg, &ctx, dest);
}

/**
 A := pkA
 K := session_key (or secret)
 
 H(A | M | K)
 */
static void calculate_H_AMK(enum hash_alg alg, unsigned char *dest, const BIGNUM *A, const unsigned char *M,
                            const unsigned char *K, int K_len)
{
    HashCTX ctx;
    
    hash_init(alg, &ctx);
    
    update_hash_n(alg, &ctx, A);
    hash_update(alg, &ctx, M, hash_length(alg));
    hash_update(alg, &ctx, K, K_len);
    
    hash_final(alg, &ctx, dest);
}


/**
 Calculate M1 (client proof).
 */
void srp_user_process_challenge(struct srp_user_s *user, const unsigned char *bytes_s, int len_s,
                                const unsigned char *bytes_B, int len_B, const unsigned char **bytes_M, int *len_M)
{
    BIGNUM *s, *B, *k, *v;
    BIGNUM *tmp1, *tmp2, *tmp3;
    BIGNUM *u, *x;
    
    *len_M = 0;
    *bytes_M = 0;
    
    BIGNUM_bin2bn(s, bytes_s, len_s);
    BIGNUM_bin2bn(B, bytes_B, len_B);
    k = H_nn_pad(user->alg, user->ng->N, user->ng->g);
    BIGNUM_new(v);
    BIGNUM_new(tmp1);
    BIGNUM_new(tmp2);
    BIGNUM_new(tmp3);
    
    if (!s || !B || !k || !v || !tmp1 || !tmp2 || !tmp3) goto cleanup1;
    
    u = H_nn_pad(user->alg, user->A, B);
    x = calculate_x(user->alg, s, user->username, user->password, user->password_len);
    if (!u || !x) goto cleanup2;
    
    // SRP-6a safety check
    if (!BIGNUM_is_zero(B) && !BIGNUM_is_zero(u))
    {
        BIGNUM_modexp(v, user->ng->g, x, user->ng->N);
        
        // S = (B - k*(g^x)) ^ (a + ux)
        BIGNUM_mul(tmp1, u, x);
        BIGNUM_add(tmp2, user->a, tmp1);        // tmp2 = (a + ux)
        BIGNUM_modexp(tmp1, user->ng->g, x, user->ng->N);
        BIGNUM_mul(tmp3, k, tmp1);             // tmp3 = k*(g^x)
        BIGNUM_sub(tmp1, B, tmp3);             // tmp1 = (B - K*(g^x))
        BIGNUM_modexp(user->S, tmp1, tmp2, user->ng->N);
        
        user->session_key_len = hash_session_key(user->alg, user->S, user->session_key);
        
        calculate_M(user->alg, user->ng, user->M, user->username, s, user->A, B, user->session_key,
                    user->session_key_len);
        calculate_H_AMK(user->alg, user->H_AMK, user->A, user->M, user->session_key, user->session_key_len);
        
        *bytes_M = user->M;
        if (len_M) *len_M = hash_length(user->alg);
    }
    else
    {
        *bytes_M = NULL;
        if (len_M) *len_M   = 0;
    }
    
cleanup2:
    BIGNUM_free(x);
    BIGNUM_free(u);
cleanup1:
    BIGNUM_free(tmp3);
    BIGNUM_free(tmp2);
    BIGNUM_free(tmp1);
    BIGNUM_free(v);
    BIGNUM_free(k);
    BIGNUM_free(B);
    BIGNUM_free(s);
}
