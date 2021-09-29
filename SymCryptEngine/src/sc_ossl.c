//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "sc_ossl.h"
#include "sc_ossl_ecc.h"
#include "sc_ossl_rsa.h"
#include "sc_ossl_dsa.h"
#include "sc_ossl_dh.h"
#include "sc_ossl_digests.h"
#include "sc_ossl_ciphers.h"
#include "sc_ossl_pkey_meths.h"
#include "sc_ossl_rand.h"
#include "sc_ossl_helpers.h"
#include <symcrypt.h>


#ifdef __cplusplus
extern "C" {
#endif

int sc_ossl_module_initialized = 0;

/* The constants used when creating the ENGINE */
static const char* engine_sc_ossl_id = "symcrypt";
static const char* engine_sc_ossl_name = "Symcrypt Engine";
static EC_KEY_METHOD* sc_ossl_eckey_method = NULL;
static RSA_METHOD* sc_ossl_rsa_method = NULL;
// static DSA_METHOD* sc_ossl_dsa_method = NULL;
// static DH_METHOD* sc_ossl_dh_method = NULL;

int sc_ossl_destroy(ENGINE* e)
{
    sc_ossl_destroy_digests();
    sc_ossl_destroy_ciphers();
    sc_ossl_destroy_pkey_methods();
    RSA_meth_free(sc_ossl_rsa_method);
    sc_ossl_rsa_method = NULL;
    sc_ossl_destroy_ecc_curves();
    EC_KEY_METHOD_free(sc_ossl_eckey_method);
    sc_ossl_eckey_method = NULL;
    CRYPTO_free_ex_index(CRYPTO_EX_INDEX_RSA, rsa_sc_ossl_idx);
    CRYPTO_free_ex_index(CRYPTO_EX_INDEX_EC_KEY, eckey_sc_ossl_idx);
    // DSA_meth_free(sc_ossl_dsa_method);
    // sc_ossl_dsa_method = NULL;
    // DH_meth_free(sc_ossl_dh_method);
    // sc_ossl_dh_method = NULL;
    return 1;
}

static int engine_set_defaults(ENGINE* e)
{
    if(    !ENGINE_set_default_digests(e)
        || !ENGINE_set_default_ciphers(e)
        || !ENGINE_set_default_pkey_meths(e)
        || !ENGINE_set_default_RSA(e)
        || !ENGINE_set_default_EC(e)
        || !ENGINE_set_default_RAND(e)
        // || !ENGINE_set_default_DSA(e)
        // || !ENGINE_set_default_DH(e)
        )
    {
        return 0;
    }
    return 1;
}

static int bind_sc_ossl_engine(ENGINE* e)
{
    if( !sc_ossl_module_initialized )
    {
        SymCryptModuleInit(SYMCRYPT_CODE_VERSION_API, SYMCRYPT_CODE_VERSION_MINOR, SYMCRYPT_CODE_VERSION_PATCH);
        sc_ossl_module_initialized = 1;
    }

    sc_ossl_eckey_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    sc_ossl_rsa_method = RSA_meth_new("Symcrypt RSA Method", 0);
    // sc_ossl_dsa_method = DSA_meth_dup(DSA_OpenSSL());
    // sc_ossl_dh_method = DH_meth_dup(DH_OpenSSL());

    if( !sc_ossl_rsa_method
     || !sc_ossl_eckey_method
     // || !sc_ossl_dsa_method
     // || !sc_ossl_dh_method
        )
    {
        goto memerr;
    }

    /* Setup RSA_METHOD */
    if( (rsa_sc_ossl_idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL)) == -1
        || !RSA_meth_set_pub_enc(sc_ossl_rsa_method, sc_ossl_rsa_pub_enc)
        || !RSA_meth_set_priv_dec(sc_ossl_rsa_method, sc_ossl_rsa_priv_dec)
        || !RSA_meth_set_priv_enc(sc_ossl_rsa_method, sc_ossl_rsa_priv_enc)
        || !RSA_meth_set_pub_dec(sc_ossl_rsa_method, sc_ossl_rsa_pub_dec)
        || !RSA_meth_set_mod_exp(sc_ossl_rsa_method, sc_ossl_rsa_mod_exp)
        || !RSA_meth_set_bn_mod_exp(sc_ossl_rsa_method, sc_ossl_rsa_bn_mod_exp)
        || !RSA_meth_set_init(sc_ossl_rsa_method, sc_ossl_rsa_init)
        || !RSA_meth_set_finish(sc_ossl_rsa_method, sc_ossl_rsa_finish)
        || !RSA_meth_set_sign(sc_ossl_rsa_method, sc_ossl_rsa_sign)
        || !RSA_meth_set_verify(sc_ossl_rsa_method, sc_ossl_rsa_verify)
        || !RSA_meth_set_keygen(sc_ossl_rsa_method, sc_ossl_rsa_keygen)
        )
    {
        goto memerr;
    }

    if( (eckey_sc_ossl_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, NULL)) == -1)
    {
        goto memerr;
    }

    /* Setup EC_METHOD */
    EC_KEY_METHOD_set_init(sc_ossl_eckey_method,
                           NULL, // eckey_init - lazily initialize ex_data only when the engine needs to
                           sc_ossl_eckey_finish,
                           NULL, // eckey_copy
                           NULL, // eckey_set_group
                           NULL, // eckey_set_private
                           NULL); // eckey_set_public
    EC_KEY_METHOD_set_keygen(sc_ossl_eckey_method,
                             sc_ossl_eckey_keygen);
    EC_KEY_METHOD_set_compute_key(sc_ossl_eckey_method,
                                  sc_ossl_eckey_compute_key);
    EC_KEY_METHOD_set_sign(sc_ossl_eckey_method,
                           sc_ossl_eckey_sign,
                           sc_ossl_eckey_sign_setup,
                           sc_ossl_eckey_sign_sig);
    EC_KEY_METHOD_set_verify(sc_ossl_eckey_method,
                             sc_ossl_eckey_verify,
                             sc_ossl_eckey_verify_sig);

    // /* Setup DSA METHOD */
    // if (   !DSA_meth_set_sign(sc_ossl_dsa_method, sc_ossl_dsa_sign)
    //     || !DSA_meth_set_sign_setup(sc_ossl_dsa_method, sc_ossl_dsa_sign_setup)
    //     || !DSA_meth_set_verify(sc_ossl_dsa_method, sc_ossl_dsa_verify)
    //     || !DSA_meth_set_init(sc_ossl_dsa_method, sc_ossl_dsa_init)
    //     || !DSA_meth_set_finish(sc_ossl_dsa_method, sc_ossl_dsa_finish)
    //     )
    // {
    //     goto memerr;
    // }

    // /* Setup DH METHOD */
    // if (   !DH_meth_set_generate_key(sc_ossl_dh_method, sc_ossl_dh_generate_key)
    //     || !DH_meth_set_compute_key(sc_ossl_dh_method, sc_ossl_dh_compute_key)
    //     || !DH_meth_set_bn_mod_exp(sc_ossl_dh_method, sc_ossl_dh_bn_mod_exp)
    //     || !DH_meth_set_init(sc_ossl_dh_method, sc_ossl_dh_init)
    //     || !DH_meth_set_finish(sc_ossl_dh_method, sc_ossl_dh_finish)
    //     )
    // {
    //     goto memerr;
    // }

    // Engine initialization
    if(    !ENGINE_set_id(e, engine_sc_ossl_id)
        || !ENGINE_set_name(e, engine_sc_ossl_name)
        || !ENGINE_set_destroy_function(e, sc_ossl_destroy)
        || !ENGINE_set_EC(e, sc_ossl_eckey_method)
        || !ENGINE_set_RSA(e, sc_ossl_rsa_method)
        //|| !ENGINE_set_DSA(e, sc_ossl_dsa_method)
        //|| !ENGINE_set_DH(e, sc_ossl_dh_method)
        || !ENGINE_set_RAND(e, sc_ossl_rand_method())
        || !ENGINE_set_digests(e, sc_ossl_digests)
        || !ENGINE_set_ciphers(e, sc_ossl_ciphers)
        || !ENGINE_set_pkey_meths(e, sc_ossl_pkey_methods)
        )
    {
        return 0;
    }

    // Set Engine as default
    if( !engine_set_defaults(e) )
    {
        return 0;
    }

    return 1;

memerr:
    return 0;
}

# ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if( id && (strcmp(id, engine_sc_ossl_id) != 0) )
    {
        return 0;
    }
    if( !bind_sc_ossl_engine(e) )
    {
        return 0;
    }
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
# endif

static ENGINE* engine_sc_ossl(void)
{
    ENGINE* ret = ENGINE_new();
    if( ret == NULL )
    {
        return NULL;
    }
    if( !bind_sc_ossl_engine(ret) )
    {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

int engine_load_sc_ossl_int(void)
{
    int retVal = 1;
    ENGINE* symcryptEngine = engine_sc_ossl();
    if( !symcryptEngine )
    {
        goto err;
    }
    retVal = ENGINE_add(symcryptEngine);
    ENGINE_free(symcryptEngine);
    ERR_clear_error();

end:
    return retVal;
err:
    retVal = 0;
    goto end;
}

int SC_OSSL_ENGINE_Initialize()
{
    return engine_load_sc_ossl_int();
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom(
    _Out_writes_bytes_(cbBuffer)  PBYTE   pbBuffer,
    SIZE_T  cbBuffer)
{
    SYMCRYPT_ERROR status = SYMCRYPT_NO_ERROR;

    if( !RAND_bytes(pbBuffer, cbBuffer) )
    {
        status = SYMCRYPT_EXTERNAL_FAILURE;
    }

    return status;
}

#ifdef __cplusplus
}
#endif