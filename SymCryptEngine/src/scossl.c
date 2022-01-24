//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "scossl.h"
#include "scossl_ecc.h"
#include "scossl_rsa.h"
#include "scossl_dsa.h"
#include "scossl_dh.h"
#include "scossl_digests.h"
#include "scossl_ciphers.h"
#include "scossl_pkey_meths.h"
#include "scossl_rand.h"
#include "scossl_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

int scossl_module_initialized = 0;

/* The constants used when creating the ENGINE */
static const char* engine_scossl_id = "SCOSSL";
static const char* engine_scossl_name = "SymCrypt engine for OpenSSL";
static EC_KEY_METHOD* scossl_eckey_method = NULL;
static RSA_METHOD* scossl_rsa_method = NULL;
// static DSA_METHOD* scossl_dsa_method = NULL;
static DH_METHOD* scossl_dh_method = NULL;

SCOSSL_STATUS scossl_destroy(ENGINE* e)
{
    scossl_destroy_digests();
    scossl_destroy_ciphers();
    scossl_destroy_pkey_methods();
    RSA_meth_free(scossl_rsa_method);
    scossl_rsa_method = NULL;
    scossl_destroy_ecc_curves();
    EC_KEY_METHOD_free(scossl_eckey_method);
    scossl_eckey_method = NULL;
    CRYPTO_free_ex_index(CRYPTO_EX_INDEX_RSA, scossl_rsa_idx);
    CRYPTO_free_ex_index(CRYPTO_EX_INDEX_EC_KEY, scossl_eckey_idx);
    // DSA_meth_free(scossl_dsa_method);
    // scossl_dsa_method = NULL;
    scossl_destroy_safeprime_dlgroups();
    DH_meth_free(scossl_dh_method);
    scossl_dh_method = NULL;
    CRYPTO_free_ex_index(CRYPTO_EX_INDEX_DH, scossl_dh_idx);
    scossl_destroy_logging();

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS scossl_bind_engine(ENGINE* e)
{
    int ret = SCOSSL_FAILURE;

    if( !scossl_module_initialized )
    {
        SymCryptModuleInit(SYMCRYPT_CODE_VERSION_API, SYMCRYPT_CODE_VERSION_MINOR, SYMCRYPT_CODE_VERSION_PATCH);
        scossl_module_initialized = 1;
    }

    scossl_eckey_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    scossl_rsa_method = RSA_meth_new("SCOSSL RSA Method", 0);
    // scossl_dsa_method = DSA_meth_dup(DSA_OpenSSL());
    scossl_dh_method = DH_meth_dup(DH_OpenSSL());

    if( !scossl_rsa_method
     || !scossl_eckey_method
     // || !scossl_dsa_method
     || !scossl_dh_method
        )
    {
        goto end;
    }

    /* Setup RSA_METHOD */
    if( (scossl_rsa_idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL)) == -1
        || !RSA_meth_set_pub_enc(scossl_rsa_method, scossl_rsa_pub_enc)
        || !RSA_meth_set_priv_dec(scossl_rsa_method, scossl_rsa_priv_dec)
        || !RSA_meth_set_priv_enc(scossl_rsa_method, scossl_rsa_priv_enc)
        || !RSA_meth_set_pub_dec(scossl_rsa_method, scossl_rsa_pub_dec)
        || !RSA_meth_set_mod_exp(scossl_rsa_method, scossl_rsa_mod_exp)
        || !RSA_meth_set_bn_mod_exp(scossl_rsa_method, scossl_rsa_bn_mod_exp)
        || !RSA_meth_set_init(scossl_rsa_method, scossl_rsa_init)
        || !RSA_meth_set_finish(scossl_rsa_method, scossl_rsa_finish)
        || !RSA_meth_set_sign(scossl_rsa_method, scossl_rsa_sign)
        || !RSA_meth_set_verify(scossl_rsa_method, scossl_rsa_verify)
        || !RSA_meth_set_keygen(scossl_rsa_method, scossl_rsa_keygen)
        )
    {
        goto end;
    }

    if( (scossl_eckey_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, NULL)) == -1)
    {
        goto end;
    }

    /* Setup EC_METHOD */
    EC_KEY_METHOD_set_init(scossl_eckey_method,
                           NULL, // eckey_init - lazily initialize ex_data only when the engine needs to
                           scossl_eckey_finish,
                           NULL, // eckey_copy
                           NULL, // eckey_set_group
                           NULL, // eckey_set_private
                           NULL); // eckey_set_public
    EC_KEY_METHOD_set_keygen(scossl_eckey_method,
                             scossl_eckey_keygen);
    EC_KEY_METHOD_set_compute_key(scossl_eckey_method,
                                  scossl_eckey_compute_key);
    EC_KEY_METHOD_set_sign(scossl_eckey_method,
                           scossl_eckey_sign,
                           scossl_eckey_sign_setup,
                           scossl_eckey_sign_sig);
    EC_KEY_METHOD_set_verify(scossl_eckey_method,
                             scossl_eckey_verify,
                             scossl_eckey_verify_sig);

    // /* Setup DSA METHOD */
    // if (   !DSA_meth_set_sign(scossl_dsa_method, scossl_dsa_sign)
    //     || !DSA_meth_set_sign_setup(scossl_dsa_method, scossl_dsa_sign_setup)
    //     || !DSA_meth_set_verify(scossl_dsa_method, scossl_dsa_verify)
    //     || !DSA_meth_set_init(scossl_dsa_method, scossl_dsa_init)
    //     || !DSA_meth_set_finish(scossl_dsa_method, scossl_dsa_finish)
    //     )
    // {
    //     goto end;
    // }

    if( (scossl_dh_idx = DH_get_ex_new_index(0, NULL, NULL, NULL, NULL)) == -1)
    {
        goto end;
    }

    // /* Setup DH METHOD */
    if (   !DH_meth_set_generate_key(scossl_dh_method, scossl_dh_generate_key)
        || !DH_meth_set_compute_key(scossl_dh_method, scossl_dh_compute_key)
        || !DH_meth_set_finish(scossl_dh_method, scossl_dh_finish)
        )
    {
        goto end;
    }

    // Engine initialization
    if(    !ENGINE_set_id(e, engine_scossl_id)
        || !ENGINE_set_name(e, engine_scossl_name)
        || !ENGINE_set_destroy_function(e, scossl_destroy)
        || !ENGINE_set_EC(e, scossl_eckey_method)
        || !ENGINE_set_RSA(e, scossl_rsa_method)
        //|| !ENGINE_set_DSA(e, scossl_dsa_method)
        || !ENGINE_set_DH(e, scossl_dh_method)
        || !ENGINE_set_RAND(e, scossl_rand_method())
        || !ENGINE_set_digests(e, scossl_digests)
        || !ENGINE_set_ciphers(e, scossl_ciphers)
        || !ENGINE_set_pkey_meths(e, scossl_pkey_methods)
        )
    {
        goto end;
    }

    // Set Engine as default
    if(    !ENGINE_set_default_digests(e)
        || !ENGINE_set_default_ciphers(e)
        || !ENGINE_set_default_pkey_meths(e)
        || !ENGINE_set_default_RSA(e)
        || !ENGINE_set_default_EC(e)
        || !ENGINE_set_default_RAND(e)
        // || !ENGINE_set_default_DSA(e)
        || !ENGINE_set_default_DH(e)
        )
    {
        goto end;
    }

    // Also set our engine as the global default for ECC/RSA so that other engines which call through
    // the default methods will call into our methods
    RSA_set_default_method(ENGINE_get_RSA(e));
    EC_KEY_set_default_method(ENGINE_get_EC(e));

    // Register the Engine as a source of OpenSSL errors and create logging lock
    scossl_setup_logging();

    // Initialize hidden static variables once at Engine load time
    if(    !scossl_ecc_init_static()
        || !scossl_dh_init_static()
        || !scossl_digests_init_static()
        || !scossl_ciphers_init_static()
        || !scossl_pkey_methods_init_static()
        )
    {
        scossl_destroy(e);
        goto end;
    }

    ret = SCOSSL_SUCCESS;
end:
    return ret;
}

# ifndef OPENSSL_NO_DYNAMIC_ENGINE
static SCOSSL_STATUS scossl_bind_helper(ENGINE *e, const char *id)
{
    if( id && (strcmp(id, engine_scossl_id) != 0) )
    {
        return SCOSSL_FAILURE;
    }
    if( !scossl_bind_engine(e) )
    {
        return SCOSSL_FAILURE;
    }
    return SCOSSL_SUCCESS;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(scossl_bind_helper)
# endif

static ENGINE* engine_scossl(void)
{
    ENGINE* ret = ENGINE_new();
    if( ret == NULL )
    {
        return NULL;
    }
    if( !scossl_bind_engine(ret) )
    {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

static SCOSSL_STATUS scossl_engine_load(void)
{
    int ret = SCOSSL_FAILURE;
    ENGINE* scosslEngine = engine_scossl();
    if( !scosslEngine )
    {
        goto end;
    }
    ret = ENGINE_add(scosslEngine);
    ENGINE_free(scosslEngine);
    ERR_clear_error();

    ret = SCOSSL_SUCCESS;
end:
    return ret;
}

int SCOSSL_ENGINE_Initialize()
{
    return scossl_engine_load();
}

#ifdef __cplusplus
}
#endif