//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_scossl_sshkdf.h"
#include <openssl/kdf.h>

// EVP_KDF_IMPL and EVP_KDF_METHOD
#include "crypto/evp.h"

// evp_kdf_ctx_st
#include "../crypto/evp/evp_local.h"


#ifdef __cplusplus
extern "C" {
#endif

#define SSH_KDF_MAX_DIGEST_SIZE (512 / 8)


struct evp_kdf_impl_st {
    PCSYMCRYPT_HASH pHash;
    unsigned char*  pbKey;
    size_t          cbKey;
    unsigned char   pbHashValue[SSH_KDF_MAX_DIGEST_SIZE];
    size_t          cbHashValue;
    unsigned char   pbSessionId[SSH_KDF_MAX_DIGEST_SIZE];
    size_t          cbSessionId;
    unsigned char   label;
};


EVP_KDF_IMPL* e_scossl_sshkdf_new()
{
    EVP_KDF_IMPL *impl = OPENSSL_zalloc(sizeof(*impl));

    if (!impl) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_NEW, ERR_R_MALLOC_FAILURE,
            "OPENSSL_zalloc return NULL");
    }

    return impl;
}

void e_scossl_sshkdf_reset(EVP_KDF_IMPL *impl)
{
    OPENSSL_clear_free(impl->pbKey, impl->cbKey);
    memset(impl, 0, sizeof(*impl));
}

void e_scossl_sshkdf_free(EVP_KDF_IMPL *impl)
{
    e_scossl_sshkdf_reset(impl);
    OPENSSL_free(impl);
}

static PCSYMCRYPT_HASH e_scossl_get_symcrypt_hash_algorithm(const EVP_MD *md)
{
    int type = EVP_MD_type(md);

    if (type == NID_sha1)
        return SymCryptSha1Algorithm;
    if (type == NID_sha256)
        return SymCryptSha256Algorithm;
    if (type == NID_sha384)
        return SymCryptSha384Algorithm;
    if (type == NID_sha512)
        return SymCryptSha512Algorithm;
 
    SCOSSL_LOG_ERROR(SCOSSL_ERR_F_GET_SYMCRYPT_HASH_ALGORITHM, SCOSSL_ERR_R_NOT_IMPLEMENTED,
        "SymCrypt engine does not support hash algorithm %d", type);

    return NULL;
}


SCOSSL_STATUS e_scossl_sshkdf_ctrl(EVP_KDF_IMPL *impl, int cmd, va_list args)
{
    SCOSSL_STATUS ret = SCOSSL_SUCCESS;
    const unsigned char *buffer;
    size_t length;
    int value;
    const EVP_MD *md;


    switch (cmd) {

        case EVP_KDF_CTRL_SET_MD:
            md = va_arg(args, EVP_MD*);

            impl->pHash = e_scossl_get_symcrypt_hash_algorithm(EVP_MD_type(md));

            if(!impl->pHash) {
                ret = SCOSSL_FAILURE;
            }
            break;

        case EVP_KDF_CTRL_SET_KEY:
            buffer = va_arg(args, const unsigned char *);
            length = va_arg(args, size_t);

            if(impl->pbKey) {
                OPENSSL_clear_free(impl->pbKey, impl->cbKey);
                impl->cbKey = 0;
            }

            impl->pbKey = OPENSSL_memdup(buffer, length);

            if(!impl->pbKey) {
                SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_CTRL, ERR_R_MALLOC_FAILURE,
                    "OPENSSL_memdup return NULL");
                ret = SCOSSL_FAILURE;
            }
            else {
                impl->cbKey = length;
            }
            break;

        case EVP_KDF_CTRL_SET_SSHKDF_XCGHASH:
            buffer = va_arg(args, const unsigned char *);
            length = va_arg(args, size_t);

            if(length > sizeof(impl->pbHashValue)) {
                SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_CTRL, ERR_R_INTERNAL_ERROR,
                    "Hash value length too large");
                ret = SCOSSL_FAILURE;
            }

            memcpy(impl->pbHashValue, buffer, length);
            impl->cbHashValue = length;
            break;

        case EVP_KDF_CTRL_SET_SSHKDF_SESSION_ID:
            buffer = va_arg(args, const unsigned char *);
            length = va_arg(args, size_t);

            if(length > sizeof(impl->pbSessionId)) {
                SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_CTRL, ERR_R_INTERNAL_ERROR,
                    "Session ID length too large");
                ret = SCOSSL_FAILURE;
            }

            memcpy(impl->pbSessionId, buffer, length);
            impl->cbSessionId = length;
            break;

        case EVP_KDF_CTRL_SET_SSHKDF_TYPE:
            value = va_arg(args, int);

            if(value >= 0 && value <= 0xff) {
                impl->label = value;
            }
            else {
                SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_CTRL, ERR_R_INTERNAL_ERROR,
                    "Label out of range");
                ret = SCOSSL_FAILURE;
            }
            break;

        default:
            ret = SCOSSL_FAILURE;
        }

    return ret;
}

SCOSSL_STATUS e_scossl_sshkdf_call_ctrl(EVP_KDF_IMPL *impl, int cmd, ...)
{
    SCOSSL_STATUS ret;
    va_list args;

    va_start(args, cmd);

    ret = e_scossl_sshkdf_ctrl(impl, cmd, args);

    va_end(args);

    return ret;
}

SCOSSL_STATUS e_scossl_sshkdf_ctrl_str(EVP_KDF_IMPL *impl, const char *type, const char *value)
{
    SCOSSL_STATUS ret = SCOSSL_FAILURE;
    unsigned char *data;
    long length;


    if(strcmp(type, "digest") == 0 || strcmp(type, "md") == 0) {
        const EVP_MD *md = EVP_get_digestbyname(value);
        ret = e_scossl_sshkdf_call_ctrl(impl, EVP_KDF_CTRL_SET_MD, md);
    }
    else if(strcmp(type, "hexkey") == 0) {
        data = OPENSSL_hexstr2buf(value, &length);
        if(data) {
            ret = e_scossl_sshkdf_call_ctrl(impl, EVP_KDF_CTRL_SET_KEY, data, length);
            OPENSSL_free(data);
        }
    }
    else if(strcmp(type, "hexxcghash") == 0) {
        data = OPENSSL_hexstr2buf(value, &length);
        if(data) {
            ret = e_scossl_sshkdf_call_ctrl(impl, EVP_KDF_CTRL_SET_SSHKDF_XCGHASH, data, length);
            OPENSSL_free(data);
        }
    }
    else if(strcmp(type, "hexsession_id") == 0) {
        data = OPENSSL_hexstr2buf(value, &length);
        if(data) {
            ret = e_scossl_sshkdf_call_ctrl(impl, EVP_KDF_CTRL_SET_SSHKDF_SESSION_ID, data, length);
            OPENSSL_free(data);
        }
    }
    else if(strcmp(type, "type") == 0 && strlen(value) == 1) {
        ret = e_scossl_sshkdf_call_ctrl(impl, EVP_KDF_CTRL_SET_SSHKDF_TYPE, (int)(*value));
    }
    else if(strcmp(type, "key") == 0) {
        ret = e_scossl_sshkdf_call_ctrl(impl, EVP_KDF_CTRL_SET_KEY, value, strlen(value));
    }
    else if(strcmp(type, "xcghash") == 0) {
        ret = e_scossl_sshkdf_call_ctrl(impl, EVP_KDF_CTRL_SET_SSHKDF_XCGHASH, value, strlen(value));
    }
    else if(strcmp(type, "session_id") == 0) {
        ret = e_scossl_sshkdf_call_ctrl(impl, EVP_KDF_CTRL_SET_SSHKDF_SESSION_ID, value, strlen(value));
    }
    else {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_CTRL_STR, ERR_R_INTERNAL_ERROR,
            "Unknown command %s", type);
    }

    return ret;
}

size_t e_scossl_sshkdf_size(EVP_KDF_IMPL *impl)
{
    return (size_t)-1;
}

SCOSSL_STATUS e_scossl_sshkdf_derive(EVP_KDF_IMPL *impl, unsigned char *out, size_t out_len)
{
    SCOSSL_STATUS ret = SCOSSL_SUCCESS;
    SYMCRYPT_ERROR scError;

    if(!impl->pHash) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Missing Digest");
        ret = SCOSSL_FAILURE;
        goto end;
    }

    if(!impl->pbKey) {
        SCOSSL_LOG_ERROR(SCOSSL_ERR_F_SSHKDF_DERIVE, ERR_R_INTERNAL_ERROR,
            "Missing Key");
        ret = SCOSSL_FAILURE;
        goto end;
    }

    scError = SymCryptSshKdf(impl->pHash,
                            impl->pbKey, impl->cbKey,
                            impl->pbHashValue, impl->cbHashValue,
                            impl->label,
                            impl->pbSessionId, impl->cbSessionId,
                            out, out_len);

    if(scError != SYMCRYPT_NO_ERROR) {
        SCOSSL_LOG_SYMCRYPT_ERROR(SCOSSL_ERR_F_SSHKDF_DERIVE, SCOSSL_ERR_R_SYMCRYPT_FAILURE,
            "SymCryptSshKdf failed", scError);
        ret = SCOSSL_FAILURE;
    }

end:

   return ret;
}



static EVP_KDF_METHOD e_scossl_sshkdf_meth = {
    EVP_KDF_SSHKDF,
    e_scossl_sshkdf_new,
    e_scossl_sshkdf_free,
    e_scossl_sshkdf_reset,
    e_scossl_sshkdf_ctrl,
    e_scossl_sshkdf_ctrl_str,
    e_scossl_sshkdf_size,
    e_scossl_sshkdf_derive,
};

EVP_KDF_CTX* e_scossl_EVP_KDF_CTX_new_id(int id)
{
    EVP_KDF_CTX *ctx;

    if(id != EVP_KDF_SSHKDF) {
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (!ctx) {
        return NULL;
    }

    ctx->kmeth = &e_scossl_sshkdf_meth;
    ctx->impl = e_scossl_sshkdf_meth.new();

    return ctx;
}

#ifdef __cplusplus
}
#endif