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

#ifndef __SRP_H
#define __SRP_H

enum hash_alg
{
    HASH_SHA1,
    HASH_SHA224,
    HASH_SHA256,
    HASH_SHA384,
    HASH_SHA512,
};

typedef enum srp_ngtype_s
{
    SRP_NG_2048,
    SRP_NG_CUSTOM
} srp_ngtype_t;

struct srp_user_s;

// srp
struct srp_user_s *srp_user_new(enum hash_alg alg, srp_ngtype_t ng_type, const char *username,
                                       const unsigned char *bytes_password, int len_password, const char *n_hex,
                                       const char *g_hex);
void srp_user_free(struct srp_user_s *user);
int srp_user_is_authenticated(struct srp_user_s *user);
const unsigned char * srp_user_get_session_key(struct srp_user_s *user, int *key_length);
void srp_user_start_authentication(struct srp_user_s *user, const unsigned char **bytes_A, int *len_A);
void srp_user_process_challenge(struct srp_user_s *user, const unsigned char *bytes_s, int len_s,
                                const unsigned char *bytes_B, int len_B, const unsigned char **bytes_M, int *len_M);

// helper
int hash_ab(enum hash_alg alg, unsigned char *md, const unsigned char *m1, int m1_len, const unsigned char *m2,
            int m2_len);

#endif
