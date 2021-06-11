//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "e_symcrypt.h"
#include "e_symcrypt_ecc.h"
#include "e_symcrypt_rsa.h"
#include "e_symcrypt_dsa.h"
#include "e_symcrypt_dh.h"
#include "e_symcrypt_digests.h"
#include "e_symcrypt_ciphers.h"
#include "e_symcrypt_pkey_meths.h"
#include "e_symcrypt_rand.h"
#include "e_symcrypt_helpers.h"
#include <symcrypt.h>


#ifdef __cplusplus
extern "C" {
#endif

int symcrypt_module_initialized = 0;

/* The constants used when creating the ENGINE */
static const char* engine_symcrypt_id = "symcrypt";
static const char* engine_symcrypt_name = "Symcrypt Engine";
static EC_KEY_METHOD* symcrypt_eckey_method = NULL;
static RSA_METHOD* symcrypt_rsa_method = NULL;
static DSA_METHOD* symcrypt_dsa_method = NULL;
static DH_METHOD* symcrypt_dh_method = NULL;

int symcrypt_destroy(ENGINE* e)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    symcrypt_destroy_digests();
    symcrypt_destroy_ciphers();
    symcrypt_destroy_pkey_methods();
    RSA_meth_free(symcrypt_rsa_method);
    symcrypt_rsa_method = NULL;
    symcrypt_destroy_ecc_curves();
    EC_KEY_METHOD_free(symcrypt_eckey_method);
    symcrypt_eckey_method = NULL;
    // DSA_meth_free(symcrypt_dsa_method);
    // symcrypt_dsa_method = NULL;
    // DH_meth_free(symcrypt_dh_method);
    // symcrypt_dh_method = NULL;
    return 1;
}

static int engine_set_defaults(ENGINE* e)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if (   !ENGINE_set_default_digests(e)
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

static int bind_symcrypt_engine(ENGINE* e)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    PFN_eckey_copy eckey_copy_pfunc = NULL;
    PFN_eckey_set_group eckey_set_group_pfunc = NULL;
    PFN_eckey_set_private eckey_set_private_pfunc = NULL;
    PFN_eckey_set_public eckey_set_public_pfunc = NULL;

    if (!symcrypt_module_initialized) {
        SymCryptModuleInit(SYMCRYPT_CODE_VERSION_API, SYMCRYPT_CODE_VERSION_MINOR, SYMCRYPT_CODE_VERSION_PATCH);
        symcrypt_module_initialized = 1;
    }

    symcrypt_eckey_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    symcrypt_rsa_method = RSA_meth_new("Symcrypt RSA Method", 0);
    symcrypt_dsa_method = DSA_meth_dup(DSA_OpenSSL());
    symcrypt_dh_method = DH_meth_dup(DH_OpenSSL());

    if (!symcrypt_rsa_method ||
        !symcrypt_eckey_method ||
        !symcrypt_dsa_method ||
        !symcrypt_dh_method)
    {
        goto memerr;
    }

    /* Setup RSA_METHOD */
    rsa_symcrypt_idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (   !RSA_meth_set_pub_enc(symcrypt_rsa_method, symcrypt_rsa_pub_enc)
        || !RSA_meth_set_priv_dec(symcrypt_rsa_method, symcrypt_rsa_priv_dec)
        || !RSA_meth_set_priv_enc(symcrypt_rsa_method, symcrypt_rsa_priv_enc)
        || !RSA_meth_set_pub_dec(symcrypt_rsa_method, symcrypt_rsa_pub_dec)
        || !RSA_meth_set_mod_exp(symcrypt_rsa_method, symcrypt_rsa_mod_exp)
        || !RSA_meth_set_bn_mod_exp(symcrypt_rsa_method, symcrypt_rsa_bn_mod_exp)
        || !RSA_meth_set_init(symcrypt_rsa_method, symcrypt_rsa_init)
        || !RSA_meth_set_finish(symcrypt_rsa_method, symcrypt_rsa_finish)
        || !RSA_meth_set_sign(symcrypt_rsa_method, symcrypt_rsa_sign)
        || !RSA_meth_set_verify(symcrypt_rsa_method, symcrypt_rsa_verify)
        || !RSA_meth_set_keygen(symcrypt_rsa_method, symcrypt_rsa_keygen)
        )
    {
        goto memerr;
    }

    eckey_symcrypt_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, NULL);

    /* Setup EC_METHOD */
    // Need to get existing methods so that we can set Init and Finish which will
    // take care of ex_data initialization and freeing.
    EC_KEY_METHOD_get_init(symcrypt_eckey_method,
                           NULL, // Init
                           NULL, // Finish
                           &eckey_copy_pfunc,
                           &eckey_set_group_pfunc,
                           &eckey_set_private_pfunc,
                           &eckey_set_public_pfunc);
    EC_KEY_METHOD_set_init(symcrypt_eckey_method,
                           symcrypt_eckey_init,
                           symcrypt_eckey_finish,
                           eckey_copy_pfunc,
                           eckey_set_group_pfunc,
                           eckey_set_private_pfunc,
                           eckey_set_public_pfunc);
    EC_KEY_METHOD_set_keygen(symcrypt_eckey_method,
                             symcrypt_eckey_keygen);
    EC_KEY_METHOD_set_compute_key(symcrypt_eckey_method,
                                  symcrypt_eckey_compute_key);
    EC_KEY_METHOD_set_sign(symcrypt_eckey_method,
                           symcrypt_eckey_sign,
                           symcrypt_eckey_sign_setup,
                           symcrypt_eckey_sign_sig);
    EC_KEY_METHOD_set_verify(symcrypt_eckey_method,
                             symcrypt_eckey_verify,
                             symcrypt_eckey_verify_sig);

    // /* Setup DSA METHOD */
    // if (   !DSA_meth_set_sign(symcrypt_dsa_method, symcrypt_dsa_sign)
    //     || !DSA_meth_set_sign_setup(symcrypt_dsa_method, symcrypt_dsa_sign_setup)
    //     || !DSA_meth_set_verify(symcrypt_dsa_method, symcrypt_dsa_verify)
    //     || !DSA_meth_set_init(symcrypt_dsa_method, symcrypt_dsa_init)
    //     || !DSA_meth_set_finish(symcrypt_dsa_method, symcrypt_dsa_finish)
    //     )
    // {
    //     goto memerr;
    // }

    // /* Setup DH METHOD */
    // if (   !DH_meth_set_generate_key(symcrypt_dh_method, symcrypt_dh_generate_key)
    //     || !DH_meth_set_compute_key(symcrypt_dh_method, symcrypt_dh_compute_key)
    //     || !DH_meth_set_bn_mod_exp(symcrypt_dh_method, symcrypt_dh_bn_mod_exp)
    //     || !DH_meth_set_init(symcrypt_dh_method, symcrypt_dh_init)
    //     || !DH_meth_set_finish(symcrypt_dh_method, symcrypt_dh_finish)
    //     )
    // {
    //     goto memerr;
    // }

    // Engine initialization
    if (!ENGINE_set_id(e, engine_symcrypt_id)
        || !ENGINE_set_name(e, engine_symcrypt_name)
        || !ENGINE_set_destroy_function(e, symcrypt_destroy)
        || !ENGINE_set_EC(e, symcrypt_eckey_method)
        || !ENGINE_set_RSA(e, symcrypt_rsa_method)
        //|| !ENGINE_set_DSA(e, symcrypt_dsa_method)
        //|| !ENGINE_set_DH(e, symcrypt_dh_method)
        || !ENGINE_set_RAND(e, symcrypt_rand_method())
        || !ENGINE_set_digests(e, symcrypt_digests)
        || !ENGINE_set_ciphers(e, symcrypt_ciphers)
        || !ENGINE_set_pkey_meths(e, symcrypt_pkey_methods)
        )
    {
        return 0;
    }

    // Set Engine as default
    if (!engine_set_defaults(e)) {
        return 0;
    }

    return 1;

memerr:
    return 0;
}

# ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_symcrypt_id) != 0))
        return 0;
    if (!bind_symcrypt_engine(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
# endif

static ENGINE* engine_symcrypt(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    ENGINE* ret = ENGINE_new();
    if (ret == NULL)
    {
        return NULL;
    }
    if (!bind_symcrypt_engine(ret))
    {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void engine_load_symcrypt_int(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    ENGINE* symcryptEngine = engine_symcrypt();
    if (!symcryptEngine)
        return;
    ENGINE_add(symcryptEngine);
    ENGINE_free(symcryptEngine);
    ERR_clear_error();
}

int SYMCRYPT_ENGINE_Initialize()
{
    SYMCRYPT_LOG_DEBUG(NULL);
    engine_load_symcrypt_int();
    return 1;
}

SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom(
    _Out_writes_bytes_(cbBuffer)  PBYTE   pbBuffer,
    SIZE_T  cbBuffer)
{
    SYMCRYPT_ERROR status = SYMCRYPT_NO_ERROR;

    if (!RAND_bytes(pbBuffer, cbBuffer))
    {
        status = SYMCRYPT_EXTERNAL_FAILURE;
    }

    return status;
}

#ifdef __cplusplus
}
#endif
