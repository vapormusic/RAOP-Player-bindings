/*****************************************************************************
 * rtsp_client.c: RTSP Client
 *
 * Copyright (C) 2004 Shiro Ninomiya <shiron@snino.com>
 * Copyright (C) 2016 Philippe <philippe_44@outlook.com>
 * Copyright (C) 2021 David Klopp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.
 *****************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "platform.h"
#include <ctype.h>

#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/evp.h>

#include "plist.h"

#include "../include/external_calls.h"
#include "../include/ed25519_signature.h"
#include "../include/curve25519_dh.h"
#include "sha512.h"

#include "aexcl_lib.h"
#include "rtsp_client.h"
#include "srp.h"

#define MAX_NUM_KD 20

typedef struct digest_info_s {
    char *user;
    char *realm;
    char *nonce;
    char *pw;
} digest_info_t;

typedef struct rtspcl_s {
    int fd;
    char url[128];
    int cseq;
    key_data_t exthds[MAX_KD];
    char *session;
    const char *useragent;
    struct in_addr local_addr;
    struct digest_info_s *digest_info;
} rtspcl_t;

extern log_level 	raop_loglevel;
static log_level	*loglevel = &raop_loglevel;

static bool exec_request(rtspcl_t *rtspcld, char *cmd, char *content_type,
                         char *content, int length, int get_response, key_data_t *hds,
                         key_data_t *kd, char **resp_content, int *resp_len,
                         char* url);


/*----------------------------------------------------------------------------*/
int rtspcl_get_serv_sock(struct rtspcl_s *p)
{
    return p->fd;
}


/*----------------------------------------------------------------------------*/
struct rtspcl_s *rtspcl_create(char *useragent)
{
    rtspcl_t *rtspcld;
    
    rtspcld = malloc(sizeof(rtspcl_t));
    memset(rtspcld, 0, sizeof(rtspcl_t));
    rtspcld->useragent = useragent;
    rtspcld->fd = -1;
    return rtspcld;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_is_connected(struct rtspcl_s *p)
{
    if (p->fd == -1) return false;
    
    return rtspcl_is_sane(p);
}


/*----------------------------------------------------------------------------*/
bool rtspcl_is_sane(struct rtspcl_s *p)
{
    int n;
    struct pollfd pfds;
    
    pfds.fd = p->fd;
    pfds.events = POLLOUT;
    
    if (p->fd == -1) return true;
    
    n = poll(&pfds, 1, 0);
    if (n == -1 || (pfds.revents & POLLERR) || (pfds.revents & POLLHUP)) return false;
    
    return true;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_connect(struct rtspcl_s *p, struct in_addr local, struct in_addr host, u16_t destport, char *sid)
{
    u16_t myport=0;
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    
    if (!p) return false;
    
    p->session = NULL;
    if ((p->fd = open_tcp_socket(local, &myport)) == -1) return false;
    if (!get_tcp_connect_by_host(p->fd, host, destport)) return false;
    
    getsockname(p->fd, (struct sockaddr*)&name, &namelen);
    memcpy(&p->local_addr,&name.sin_addr, sizeof(struct in_addr));
    
    sprintf(p->url,"rtsp://%s/%s", inet_ntoa(host), sid);
    
    return true;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_disconnect(struct rtspcl_s *p)
{
    bool rc = true;
    
    if (!p) return false;
    
    if (p->fd != -1) {
        rc = exec_request(p, "TEARDOWN", NULL, NULL, 0, 1, NULL, NULL, NULL, NULL, NULL);
        closesocket(p->fd);
    }
    
    p->fd = -1;
    
    return rc;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_destroy(struct rtspcl_s *p)
{
    bool rc;
    
    if (!p) return false;
    
    rc = rtspcl_disconnect(p);
    
    if (p->session) free(p->session);
    if (p->digest_info && p->digest_info->realm) free(p->digest_info->realm);
    if (p->digest_info && p->digest_info->nonce) free(p->digest_info->nonce);
    if (p->digest_info && p->digest_info->pw) free(p->digest_info->pw);
    if (p->digest_info) free(p->digest_info);
    free(p);
    
    return rc;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_add_exthds(struct rtspcl_s *p, char *key, char *data)
{
    int i = 0;
    
    if (!p) return false;
    
    while (p->exthds[i].key && i < MAX_KD - 1) {
        if ((unsigned char) p->exthds[i].key[0] == 0xff) break;
        i++;
    }
    
    if (i == MAX_KD - 2) return false;
    
    if (p->exthds[i].key) {
        free(p->exthds[i].key);
        free(p->exthds[i].data);
    }
    else p->exthds[i + 1].key = NULL;
    
    p->exthds[i].key = strdup(key);
    p->exthds[i].data = strdup(data);
    
    return true;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_mark_del_exthds(struct rtspcl_s *p, char *key)
{
    int i = 0;
    
    if (!p) return false;
        
    while (p->exthds[i].key) {
        if (!strcmp(key, p->exthds[i].key)){
            p->exthds[i].key[0]=0xff;
            return true;
        }
        i++;
    }
    
    return false;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_remove_all_exthds(struct rtspcl_s *p)
{
    int i = 0;
    
    if (!p) return false;
    
    while (p->exthds[i].key) {
        free(p->exthds[i].key);
        free(p->exthds[i].data);
        i++;
    }
    memset(p->exthds, 0, sizeof(p->exthds));
    
    return true;
}


/*----------------------------------------------------------------------------*/
char* rtspcl_local_ip(struct rtspcl_s *p)
{
    static char buf[16];
    
    if (!p) return NULL;
    
    return strcpy(buf, inet_ntoa(p->local_addr));
}


/*----------------------------------------------------------------------------*/

/*
 calculate the di_response for a given digest_info and store it in the response array
 */
static inline void get_di_response(struct digest_info_s *digest_info, char *url, char *method, char **response) {
    char *user = digest_info->user;
    char *realm = digest_info->realm;
    char *nonce = digest_info->nonce;
    char *pw = digest_info->pw;
    
    char *tmp;
    size_t size;
    
    // calculate h1
    size = strlen(user) + strlen(realm) + strlen(pw) + 3;
    tmp = (char *)malloc(size);
    strcat(tmp, user);
    strcat(tmp + strlen(tmp), ":");
    strcat(tmp + strlen(tmp), realm);
    strcat(tmp + strlen(tmp), ":");
    strcat(tmp + strlen(tmp), pw);
    unsigned char ha1[16];
    MD5((unsigned char *)tmp, strlen(tmp), ha1);
    free(tmp);
    
    // calculate h2
    size = strlen(method) + strlen(url) + 2;
    tmp = (char *)malloc(size);
    strcat(tmp, method);
    strcat(tmp + strlen(tmp), ":");
    strcat(tmp + strlen(tmp), url);
    
    unsigned char ha2[16];
    MD5((unsigned char *)tmp, strlen(tmp), ha2);
    free(tmp);
    
    // create di_response
    char *ha1_md5 = NULL, *ha2_md5 = NULL;
    bytes2hex(ha1, 16, &ha1_md5);
    bytes2hex(ha2, 16, &ha2_md5);
    
    size = strlen(ha1_md5) + strlen(nonce) + strlen(ha2_md5) + 3;
    tmp = (char *)malloc(size);
    strcat(tmp, ha1_md5);
    strcat(tmp + strlen(tmp), ":");
    strcat(tmp + strlen(tmp), nonce);
    strcat(tmp + strlen(tmp), ":");
    strcat(tmp + strlen(tmp), ha2_md5);
    
    unsigned char di_response[16];
    MD5((unsigned char *)tmp, strlen(tmp), di_response);
    free(tmp);
    
    free(ha1_md5);
    free(ha2_md5);
    
    bytes2hex(di_response, 16, response);
}

bool rtspcl_announce_sdp(struct rtspcl_s *p, char *sdp, char *password)
{
    if(!p) return false;
    
    if (password) {
        char *temp, *found, *realm, *nonce;
        key_data_t kd[MAX_KD];
        //kd[0].key = NULL;
        // execute an announce request and parse the output to get realm and nonce
        exec_request(p, "ANNOUNCE", "application/sdp", sdp, 0, 1, NULL, kd, NULL, NULL, NULL);
        
        if ((temp = kd_lookup(kd, "WWW-Authenticate")) != NULL) {
            int i;
            for (i=0, found = strtok(temp, "\"");  i < 4 && found != NULL; ++i, found = strtok(NULL, "\"")) {
                if (i == 1) realm = found;
                if (i == 3) nonce = found;
            };
            free_kd(kd);
            
            // error if the realm or nonce could not be found
            if (i != 4) return false;
            
            p->digest_info = malloc(sizeof(digest_info_t));
            p->digest_info->user = strcmp(realm, "raop") == 0  ? "iTunes" : "AirPlay";
            p->digest_info->pw = strdup(password);
            p->digest_info->realm = strdup(realm);
            p->digest_info->nonce = strdup(nonce);
        } else {
            free_kd(kd);
            return false;
        }
    }
    
    return exec_request(p, "ANNOUNCE", "application/sdp", sdp, 0, 1, NULL, NULL, NULL, NULL, NULL);
}


/*----------------------------------------------------------------------------*/
bool rtspcl_setup(struct rtspcl_s *p, struct rtp_port_s *port, key_data_t *rkd)
{
    key_data_t hds[2];
    char *temp;
    
    if (!p) return false;
    
    port->audio.rport = 0;
    
    hds[0].key = "Transport";
    hds[0].data = _aprintf("RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port=%d;timing_port=%d",
                           (unsigned) port->ctrl.lport, (unsigned) port->time.lport);
    if (!hds[0].data) return false;
    hds[1].key = NULL;
    
    if (!exec_request(p, "SETUP", NULL, NULL, 0, 1, hds, rkd, NULL, NULL, NULL)) return false;
    free(hds[0].data);
    
    if ((temp = kd_lookup(rkd, "Session")) != NULL) {
        p->session = strdup(trim(temp));
        LOG_DEBUG("[%p]: <------- : %s: session:%s",p , p->session);
        return true;
    }
    else {
        free_kd(rkd);
        LOG_ERROR("[%p]: no session in response", p);
        return false;
    }
}


/*----------------------------------------------------------------------------*/
bool rtspcl_record(struct rtspcl_s *p, u16_t start_seq, u32_t start_ts, key_data_t *rkd)
{
    bool rc;
    key_data_t hds[3];
    
    if (!p) return false;
    
    if (!p->session){
        LOG_ERROR("[%p]: no session in progress", p);
        return false;
    }
    
    hds[0].key 	= "Range";
    hds[0].data = "npt=0-";
    hds[1].key 	= "RTP-Info";
    hds[1].data = _aprintf("seq=%u;rtptime=%u", (unsigned) start_seq, (unsigned) start_ts);
    if (!hds[1].data) return false;
    hds[2].key	= NULL;
    
    rc = exec_request(p, "RECORD", NULL, NULL, 0, 1, hds, rkd, NULL, NULL, NULL);
    free(hds[1].data);
    
    return rc;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_set_parameter(struct rtspcl_s *p, char *param)
{
    if (!p) return false;
    
    return exec_request(p, "SET_PARAMETER", "text/parameters", param, 0, 1, NULL, NULL, NULL, NULL, NULL);
}


/*----------------------------------------------------------------------------*/
bool rtspcl_set_artwork(struct rtspcl_s *p, u32_t timestamp, char *content_type, int size, char *image)
{
    key_data_t hds[2];
    char rtptime[20];
    
    if (!p) return false;
    
    sprintf(rtptime, "rtptime=%u", timestamp);
    
    hds[0].key	= "RTP-Info";
    hds[0].data	= rtptime;
    hds[1].key	= NULL;
    
    return exec_request(p, "SET_PARAMETER", content_type, image, size, 2, hds, NULL, NULL, NULL, NULL);
}


/*----------------------------------------------------------------------------*/
bool rtspcl_set_daap(struct rtspcl_s *p, u32_t timestamp, int count, va_list args)
{
    key_data_t hds[2];
    char rtptime[20];
    char *q, *str;
    bool rc;
    int i;
    
    if (!p) return false;
    
    str = q = malloc(1024);
    if (!str) return false;
    
    sprintf(rtptime, "rtptime=%u", timestamp);
    
    hds[0].key	= "RTP-Info";
    hds[0].data	= rtptime;
    hds[1].key	= NULL;
    
    // set mandatory headers first, the final size will be set at the end
    q = (char*) memcpy(q, "mlit", 4) + 8;
    q = (char*) memcpy(q, "mikd", 4) + 4;
    for (i = 0; i < 3; i++) *q++ = 0; *q++ = 1;
    *q++ = 2;
    
    while (count-- && (q-str) < 1024) {
        char *fmt, type;
        u32_t size;
        
        fmt = va_arg(args, char*);
        type = (char) va_arg(args, int);
        q = (char*) memcpy(q, fmt, 4) + 4;
        
        switch(type) {
            case 's': {
                char *data;
                
                data = va_arg(args, char*);
                size = strlen(data);
                for (i = 0; i < 4; i++) *q++ = size >> (24-8*i);
                q = (char*) memcpy(q, data, size) + size;
                break;
            }
            case 'i': {
                int data;
                data = va_arg(args, int);
                for (i = 0; i < 3; i++) *q++ = 0; *q++ = 2;
                *q++ = (data >> 8); *q++ = data;
                break;
            }
        }
    }
    
    // set "mlit" object size
    for (i = 0; i < 4; i++) *(str + 4 + i) = (q-str-8) >> (24-8*i);
    
    rc = exec_request(p, "SET_PARAMETER", "application/x-dmap-tagged", str, q-str, 2, hds, NULL, NULL, NULL, NULL);
    free(str);
    return rc;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_options(struct rtspcl_s *p, key_data_t *rkd)
{
    if(!p) return false;
    
    return exec_request(p, "OPTIONS", NULL, NULL, 0, 1, NULL, rkd, NULL, NULL, "*");
}


/*----------------------------------------------------------------------------*/
bool rtspcl_pair_pin_start(struct rtspcl_s *p)
{
    return exec_request(p, "POST", NULL, NULL, 0, 1, NULL, NULL, NULL, NULL, "/pair-pin-start");
}


static bool _rtspcl_pair_setup_confirm_pin(struct rtspcl_s *p, char *client_id, u8_t **pkB, u64_t *pkB_size,
                                           u8_t **salt, u64_t *salt_size)
{
    plist_t dict;
    char *dict_data = NULL;
    uint32_t dict_size = 0;
    
    char *content = NULL;
    int content_size = 0;
    
    // create the binary plist to send
    dict = plist_new_dict();
    plist_dict_set_item(dict, "method", plist_new_string("pin"));
    plist_dict_set_item(dict, "user", plist_new_string(client_id));
    plist_to_bin(dict, &dict_data, &dict_size);
    
    if (!exec_request(p, "POST", "application/x-apple-binary-plist", dict_data, dict_size, 1, NULL, NULL,
                      &content, &content_size, "/pair-setup-pin") || !content_size) goto erexit;
    
    plist_to_bin_free(dict_data);
    plist_free(dict);
    
    // read and verify the response
    plist_from_bin(content, content_size, &dict);
    if (plist_dict_get_size(dict) != 2) goto erexit;
    
    plist_t pkB_node = plist_dict_get_item(dict, "pk");
    plist_t salt_node = plist_dict_get_item(dict, "salt");
    if (!pkB_node || !salt_node) goto erexit;
    
    plist_get_data_val(pkB_node, (char **)pkB, pkB_size);
    plist_get_data_val(salt_node, (char **)salt, salt_size);
    if (*pkB_size != 256 || *salt_size != 16) goto erexit;
    
    plist_free(dict);
    free(content);
    
    return true;
    
erexit:
    plist_free(dict);
    if (*pkB) {
        free(*pkB);
        pkB = NULL;
        *pkB_size = 0;
    }
    if (*salt) {
        free(*salt);
        salt = NULL;
        *salt_size = 0;
    }
    if (dict_data) plist_to_bin_free(dict_data);
    if (content) free(content);
    
    return false;
}


static bool _rtspcl_pair_setup_run_srp(struct rtspcl_s *p, const char *client_id, u8_t *pin, u64_t pin_len,
                                       u8_t *pkB, u64_t pkB_size, u8_t *salt, u64_t salt_size,
                                       unsigned char **secret, int *secret_size)
{
    plist_t dict;
    char *dict_data = NULL;
    uint32_t dict_size = 0;
    
    char *content = NULL;
    int content_size = 0;
    
    const u8_t *pkA=NULL, *M1=NULL;
    int pkA_size, M1_size;
    
    struct srp_user_s *srp_user;
    srp_user = srp_user_new(HASH_SHA1, SRP_NG_2048, client_id, (unsigned char *)pin, pin_len, 0, 0);
    srp_user_start_authentication(srp_user, &pkA, &pkA_size);
    srp_user_process_challenge(srp_user, (const unsigned char *)salt, salt_size, (const unsigned char *)pkB,
                               pkB_size, &M1, &M1_size);
    
    // Send the plist data with pkA and M1
    dict = plist_new_dict();
    plist_dict_set_item(dict, "pk", plist_new_data((char *)pkA, pkA_size));
    plist_dict_set_item(dict, "proof", plist_new_data((char *)M1, M1_size));
    plist_to_bin(dict, &dict_data, &dict_size);
    
    bool res = exec_request(p, "POST", "application/x-apple-binary-plist", dict_data, dict_size, 1, NULL, NULL,
                            &content, &content_size, "/pair-setup-pin") && content_size;
    
    // TODO: You could verify the M2 proof. This is not necessary since the Apple TV will detect errors and send a
    // TODO: HTTP 470 error code.
    
    plist_free(dict);
    if (dict_data) plist_to_bin_free(dict_data);
    if (content) free(content);
    
    // copy the secret to the output parameter
    const unsigned char *session_key = srp_user_get_session_key(srp_user, secret_size);
    *secret = malloc(*secret_size);
    memcpy((unsigned char*)*secret, session_key, *secret_size);
    
    // this will free pkA, M1 and session_key
    srp_user_free(srp_user);
    
    return res;
}

static bool _rtspcl_pair_setup_run_aes(struct rtspcl_s *p, const unsigned char *secret, int secret_size)
{
    char *AES_SETUP_KEY = "Pair-Setup-AES-Key";
    char *AES_SETUP_IV = "Pair-Setup-AES-IV";
    unsigned char key[SHA512_DIGEST_LENGTH];
    unsigned char iv[SHA512_DIGEST_LENGTH];
    
    // build AES-key & AES-iv from shared secret digest
    if (hash_ab(HASH_SHA512, key, (unsigned char *)AES_SETUP_KEY, strlen(AES_SETUP_KEY), secret, secret_size) < 0 ||
        hash_ab(HASH_SHA512, iv, (unsigned char *)AES_SETUP_IV, strlen(AES_SETUP_IV), secret, secret_size) < 0)
        return false;
    // add 0x01 to the last byte of the AES-IV
    iv[15]++;
    
    // create a public key using a Ed25519 from the secret
    u8_t auth_pub[ed25519_public_key_size], auth_priv[ed25519_private_key_size];
    ed25519_CreateKeyPair(auth_pub, auth_priv, NULL, secret);
    
    // use the AES key and IV to encode the public key created with Ed25519 using AES in GCM
    unsigned char tag[16];
    unsigned char encrypted[32];
    
    EVP_CIPHER_CTX *ctx;
    int len;
    
    if (!(ctx = EVP_CIPHER_CTX_new()) ||
        (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) ||
        (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL) != 1) ||
        (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) ) goto erexit;
    if (EVP_EncryptUpdate(ctx, encrypted, &len, auth_pub, sizeof(auth_pub)) != 1) goto erexit;
    if (len > sizeof(encrypted)) goto erexit;
    if (EVP_EncryptFinal_ex(ctx, encrypted + len, &len) != 1) goto erexit;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto erexit;
    EVP_CIPHER_CTX_free(ctx);
    
    // Send the plist data
    plist_t dict;
    char *dict_data = NULL;
    uint32_t dict_size = 0;
    
    dict = plist_new_dict();
    plist_dict_set_item(dict, "epk", plist_new_data((char *)encrypted, 32));
    plist_dict_set_item(dict, "authTag", plist_new_data((char *)tag, 16));
    plist_to_bin(dict, &dict_data, &dict_size);
    
    bool res = exec_request(p, "POST", "application/x-apple-binary-plist", dict_data, dict_size, 1, NULL, NULL, NULL,
                            NULL, "/pair-setup-pin");
    
    plist_free(dict);
    if (dict_data) plist_to_bin_free(dict_data);
    
    return res;
    
erexit:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}


bool rtspcl_pair_setup_pin(struct rtspcl_s *p, const char *pin, char **secret)
{
    int size = 0;
    unsigned char *bsecret = NULL;
    
    // generate a random 8 byte client-ID
    char client_id[8+1];
    unsigned char bclient_id[8];
    RAND_bytes(bclient_id, 8);
    sprintf(client_id, "%08x", (unsigned int)bclient_id);
    
    // Step 1: Confirm pin
    u8_t u_pin[4];
    memcpy(u_pin, pin, sizeof(u_pin));
    u8_t *salt=NULL, *pkB=NULL;
    u64_t salt_size = 0, pkB_size = 0;
    if (!_rtspcl_pair_setup_confirm_pin(p, client_id, &pkB, &pkB_size, &salt, &salt_size)) goto erexit;
    
    LOG_DEBUG("[%p]: received pk <B> and salt.", p);
    
    // Step 2: Run SRP
    if (!_rtspcl_pair_setup_run_srp(p, client_id, u_pin, sizeof(u_pin), pkB, pkB_size, salt, salt_size, &bsecret, &size))
        goto erexit;
    if (!bsecret) goto erexit;
    
    LOG_DEBUG("[%p]: received secret.", p);
    
    free(pkB);
    free(salt);
    
    // STEP 3: Run AES
    if (!_rtspcl_pair_setup_run_aes(p, bsecret, size)) goto erexit;
    
    LOG_DEBUG("[%p]: ran aes.", p);
    
    // Copy a hex representation of the secret to the output variable
    bytes2hex(bsecret, size, secret);
    free((unsigned char *)bsecret);
    
    return true;
    
erexit:
    LOG_ERROR("[%p]: Error registering pin %s.", p, pin);
    if (pkB) free(pkB);
    if (salt) free(salt);
    if (bsecret) free((unsigned char *)bsecret);
    return false;
}

bool rtspcl_pair_verify(struct rtspcl_s *p, char *secret_hex)
{
    char *AES_VERIFY_KEY = "Pair-Verify-AES-Key";
    char *AES_VERIFY_IV = "Pair-Verify-AES-IV";
    
    u8_t auth_pub[ed25519_public_key_size], auth_priv[ed25519_private_key_size];
    u8_t verify_pub[ed25519_public_key_size], verify_secret[ed25519_secret_key_size];
    u8_t atv_pub[ed25519_public_key_size], *atv_data;
    u8_t secret[ed25519_secret_key_size], shared_secret[ed25519_secret_key_size];
    u8_t *buf, *content;
    int atv_len, len;
    u8_t signed_keys[ed25519_signature_size];
    u8_t aes_key[16], aes_iv[16];
    EVP_CIPHER_CTX *ctx = NULL;
    bool rc = true;
    
    if (!p) return false;
    buf = secret;
    hex2bytes(secret_hex, &buf);
    
    // retrieve authentication keys from secret
    ed25519_CreateKeyPair(auth_pub, auth_priv, NULL, secret);
    // create a verification public key
    RAND_bytes(verify_secret, ed25519_secret_key_size);
    VALGRIND_MAKE_MEM_DEFINED(verify_secret, ed25519_secret_key_size);
    curve25519_dh_CalculatePublicKey(verify_pub, verify_secret);
    
    // POST the auth_pub and verify_pub concataned
    buf = malloc(4 + ed25519_public_key_size * 2);
    len = 0;
    memcpy(buf, "\x01\x00\x00\x00", 4); len += 4;
    memcpy(buf + len, verify_pub, ed25519_public_key_size); len += ed25519_public_key_size;
    memcpy(buf + len, auth_pub, ed25519_public_key_size); len += ed25519_public_key_size;
    
    if (!exec_request(p, "POST", "application/octet-stream", (char*) buf, len, 1, NULL, NULL, (char**) &content,
                      &atv_len, "/pair-verify")) {
        LOG_ERROR("[%p]: AppleTV verify step 1 failed (pair again)", p);
        free(buf);
        return false;
    }
    
    // get atv_pub and atv_data then create shared secret
    memcpy(atv_pub, content, ed25519_public_key_size);
    atv_data = malloc(atv_len - ed25519_public_key_size);
    memcpy(atv_data, content + ed25519_public_key_size, atv_len - ed25519_public_key_size);
    curve25519_dh_CreateSharedKey(shared_secret, atv_pub, verify_secret);
    free(content);
    
    // build AES-key & AES-iv from shared secret digest
    if (!(rc = (hash_ab(HASH_SHA512, buf, (unsigned char *)AES_VERIFY_KEY, strlen(AES_VERIFY_KEY),
                        shared_secret, ed25519_secret_key_size) >= 0))) goto fcexit;
    memcpy(aes_key, buf, 16);
    if (!(rc = (hash_ab(HASH_SHA512, buf, (unsigned char *)AES_VERIFY_IV, strlen(AES_VERIFY_IV),
                        shared_secret, sizeof(shared_secret)) >= 0))) goto fcexit;
    memcpy(aes_iv, buf, 16);
    
    // sign the verify_pub and atv_pub
    memcpy(buf, verify_pub, ed25519_public_key_size);
    memcpy(buf + ed25519_public_key_size, atv_pub, ed25519_public_key_size);
    ed25519_SignMessage(signed_keys, auth_priv, NULL, buf, ed25519_public_key_size * 2);
    
    // encrypt the signed result + atv_data
    ctx = EVP_CIPHER_CTX_new();
    if (!(rc = (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, aes_key, aes_iv) == 1))) goto fcexit;
    memcpy(buf, atv_data, atv_len - ed25519_public_key_size);
    if (!(rc = (EVP_EncryptUpdate(ctx, buf, &len, buf, atv_len - ed25519_public_key_size) == 1))) goto fcexit;
    memcpy(buf + 4, signed_keys, ed25519_signature_size);
    if (!(rc = (EVP_EncryptUpdate(ctx, buf + 4, &len, buf + 4, ed25519_signature_size) == 1))) goto fcexit;
    if (!(rc = (EVP_EncryptFinal_ex(ctx, buf+len, &len) == 1))) goto fcexit;
    // add 4 NULL bytes at the beginning
    memcpy(buf, "\x00\x00\x00\x00", 4);
    len = ed25519_signature_size + 4;
    free(atv_data);
    
    if (!exec_request(p, "POST", "application/octet-stream", (char*) buf, len, 1, NULL, NULL, NULL, NULL, "/pair-verify")) {
        LOG_ERROR("[%p]: AppleTV verify step 2 failed (pair again)", p);
        rc = false;
    }
    
fcexit:
    if (ctx) EVP_CIPHER_CTX_cleanup(ctx);
    free(buf);
    
    return rc;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_auth_setup(struct rtspcl_s *p)
{
    u8_t pub_key[ed25519_public_key_size], secret[ed25519_secret_key_size];
    u8_t *buf, *rsp;
    int rsp_len;
    
    if (!p) return false;
    
    // create a verification public key
    RAND_bytes(secret, ed25519_secret_key_size);
    VALGRIND_MAKE_MEM_DEFINED(secret, ed25519_secret_key_size);
    curve25519_dh_CalculatePublicKey(pub_key, secret);
    
    
    // POST the auth_pub and verify_pub concataned
    buf = malloc(1 + ed25519_public_key_size);
    memcpy(buf, "\x01", 1);
    memcpy(buf + 1, pub_key, ed25519_public_key_size);
    
    if (!exec_request(p, "POST", "application/octet-stream", (char*) buf,
                      ed25519_public_key_size+1, 1, NULL, NULL, (char**) &rsp, &rsp_len, "/auth-setup")) {
        LOG_ERROR("[%p]: auth-setup failed", p);
        free(buf);
        return false;
    }
    
    free(buf);
    free(rsp);
    
    return true;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_flush(struct rtspcl_s *p, u16_t seq_number, u32_t timestamp)
{
    bool rc;
    key_data_t hds[2];
    
    if(!p) return false;
    
    hds[0].key	= "RTP-Info";
    hds[0].data	= _aprintf("seq=%u;rtptime=%u", (unsigned) seq_number, (unsigned) timestamp);
    if (!hds[0].data) return false;
    hds[1].key	= NULL;
    
    rc = exec_request(p, "FLUSH", NULL, NULL, 0, 1, hds, NULL, NULL, NULL, NULL);
    free(hds[0].data);
    
    return rc;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_teardown(struct rtspcl_s *p)
{
    if (!p) return false;
    
    return exec_request(p, "TEARDOWN", NULL, NULL, 0, 1, NULL, NULL, NULL, NULL, NULL);
}

/*
 * send RTSP request, and get responce if it's needed
 * if this gets a success, *kd is allocated or reallocated (if *kd is not NULL)
 */
static bool exec_request(struct rtspcl_s *rtspcld, char *cmd, char *content_type,
                         char *content, int length, int get_response, key_data_t *hds,
                         key_data_t *rkd, char **resp_content, int *resp_len, char* url)
{
    char line[2048];
    char *req;
    char buf[256];
    const char delimiters[] = " ";
    char *token,*dp;
    int i,j, rval, len, clen;
    int timeout = 10000; // msec unit
    struct pollfd pfds;
    key_data_t lkd[MAX_KD], *pkd;
    
    if(!rtspcld || rtspcld->fd == -1) return false;
    
    pfds.fd = rtspcld->fd;
    pfds.events = POLLOUT;
    
    i = poll(&pfds, 1, 0);
    if (i == -1 || (pfds.revents & POLLERR) || (pfds.revents & POLLHUP)) return false;
    
    if ((req = malloc(4096+length)) == NULL) return false;
    
    sprintf(req, "%s %s RTSP/1.0\r\n",cmd, url ? url : rtspcld->url);
    
    for (i = 0; hds && hds[i].key != NULL; i++) {
        sprintf(buf, "%s: %s\r\n", hds[i].key, hds[i].data);
        strcat(req, buf);
    }
    
    if (content_type && content) {
        sprintf(buf, "Content-Type: %s\r\nContent-Length: %d\r\n", content_type, length ? length : (int) strlen(content));
        strcat(req, buf);
    }
    
    sprintf(buf,"CSeq: %d\r\n", ++rtspcld->cseq);
    strcat(req, buf);
    
    sprintf(buf, "User-Agent: %s\r\n", rtspcld->useragent);
    strcat(req, buf);
    
    //sprintf(buf, "Connection: keep-alive\r\n");
    //strcat(req, buf);
    
    for (i = 0; rtspcld->exthds[i].key; i++) {
        if ((unsigned char) rtspcld->exthds[i].key[0] == 0xff) continue;
        sprintf(buf,"%s: %s\r\n", rtspcld->exthds[i].key, rtspcld->exthds[i].data);
        strcat(req, buf);
    }
    
    digest_info_t *info = rtspcld->digest_info;
    if (info != NULL) {
        char *response = NULL;
        get_di_response(info, url ? url : rtspcld->url, cmd, &response);
        sprintf(buf,"Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"\r\n"
                , info->user, info->realm, info->nonce, url ? url : rtspcld->url, response);
        strcat(req, buf);
        free(response);
    }
    
    if (rtspcld->session != NULL ) {
        sprintf(buf,"Session: %s\r\n",rtspcld->session);
        strcat(req, buf);
    }
    
    strcat(req,"\r\n");
    len = strlen(req);
    
    if (content_type && content) {
        len += (length ? length : strlen(content));
        memcpy(req + strlen(req), content, length ? length : strlen(content));
        req[len] = '\0';
    }
    
    rval = send(rtspcld->fd, req, len, 0);
    LOG_DEBUG( "[%p]: ----> : write %s", rtspcld, req);
    free(req);
    
    if (rval != len) {
        LOG_ERROR( "[%p]: couldn't write request (%d!=%d)", rtspcld, rval, len );
    }
    
    if (!get_response) return true;
    
    if (read_line(rtspcld->fd, line, sizeof(line), timeout, 0) <= 0) {
        if (get_response == 1) {
            LOG_ERROR("[%p]: response : %s request failed", rtspcld, line);
            return false;
        }
        else return true;
    }
    
    token = strtok(line, delimiters);
    token = strtok(NULL, delimiters);
    // continue parsing in case of a 401 error, ANNOUNCE requires the response data to get the realm and nonce
    if (token == NULL || (strcmp(token, "200") && strcmp(token, "401"))) {
        if(get_response == 1) {
            LOG_ERROR("[%p]: <------ : request failed, error code %s", rtspcld, token);
            return false;
        }
    }
    else {
        LOG_DEBUG("[%p]: <------ : %s: request %s", rtspcld, token, strcmp(token, "200") ? "unauthorized" : "ok");
    }
    
    i = 0;
    clen = 0;
    if (rkd) pkd = rkd;
    else pkd = lkd;
    pkd[0].key = NULL;
    
    while (read_line(rtspcld->fd, line, sizeof(line), timeout, 0) > 0) {
        LOG_DEBUG("[%p]: <------ : %s", rtspcld, line);
        timeout = 1000; // once it started, it shouldn't take a long time
        
        if (i && line[0] == ' ') {
            for(j = 0; j < strlen(line); j++) if (line[j] != ' ') break;
            pkd[i].data = strdup(line + j);
            continue;
        }
        
        dp = strstr(line,":");
        
        if (!dp){
            LOG_ERROR("[%p]: Request failed, bad header", rtspcld);
            free_kd(pkd);
            return false;
        }
        
        *dp = 0;
        pkd[i].key = strdup(line);
        pkd[i].data = strdup(dp + 1);
        
        if (!strcasecmp(pkd[i].key, "Content-Length")) clen = atol(pkd[i].data);
        
        i++;
    }
    
    if (clen) {
        char *data = malloc(clen);
        int size = 0;
        
        while (data && size < clen) {
            int bytes = recv(rtspcld->fd, data + size, clen - size, 0);
            if (bytes <= 0) break;
            size += bytes;
        }
        
        if (!data || size != clen) {
            LOG_ERROR("[%p]: content length receive error %p %d", rtspcld, data, size);
        }
        
        LOG_INFO("[%p]: Body data %d, %s", rtspcld, clen, data);
        if (resp_content) {
            *resp_content = data;
            if (resp_len) *resp_len = clen;
        } else free(data);
    }
    
    pkd[i].key = NULL;
    if (!rkd) free_kd(pkd);
    
    return strcmp(token, "200");
}
