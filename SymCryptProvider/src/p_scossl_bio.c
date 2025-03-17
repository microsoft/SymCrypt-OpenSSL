//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "p_scossl_bio.h"

#ifdef __cplusplus
extern "C" {
#endif

OSSL_FUNC_BIO_read_ex_fn *core_bio_read_ex = NULL;
OSSL_FUNC_BIO_write_ex_fn *core_bio_write_ex = NULL;
OSSL_FUNC_BIO_up_ref_fn *core_bio_up_ref = NULL;
OSSL_FUNC_BIO_free_fn *core_bio_free = NULL;
OSSL_FUNC_BIO_gets_fn *core_bio_gets = NULL;
OSSL_FUNC_BIO_puts_fn *core_bio_puts = NULL;
OSSL_FUNC_BIO_ctrl_fn *core_bio_ctrl = NULL;

static SCOSSL_STATUS p_scossl_bio_core_read_ex(BIO *bio, char *data, size_t data_len,
                                               size_t *bytes_read)
{
    if (core_bio_read_ex == NULL)
        return SCOSSL_FAILURE;

    return core_bio_read_ex(BIO_get_data(bio), data, data_len, bytes_read);
}

static SCOSSL_STATUS p_scossl_bio_core_write_ex(BIO *bio, const char *data, size_t data_len,
                                                size_t *written)
{
    if (core_bio_write_ex == NULL)
        return SCOSSL_FAILURE;

    return core_bio_write_ex(BIO_get_data(bio), data, data_len, written);
}

static SCOSSL_STATUS p_scossl_bio_core_create(BIO *bio)
{
    BIO_set_init(bio, 1);

    return SCOSSL_SUCCESS;
}

static SCOSSL_STATUS p_scossl_bio_core_destroy(BIO *bio)
{
    BIO_set_init(bio, 0);

    if (core_bio_free != NULL)
        core_bio_free(BIO_get_data(bio));

    return SCOSSL_SUCCESS;
}

static int p_scossl_bio_core_gets(BIO *bio, char *buf, int size)
{
    if (core_bio_gets == NULL)
        return 0;

    return core_bio_gets(BIO_get_data(bio), buf, size);
}

static int p_scossl_bio_core_puts(BIO *bio, const char *str)
{
    if (core_bio_puts == NULL)
        return 0;

    return core_bio_puts(BIO_get_data(bio), str);
}

static long p_scossl_bio_core_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    if (core_bio_ctrl == NULL)
        return 0;

    return core_bio_ctrl(BIO_get_data(bio), cmd, num, ptr);
}

_Use_decl_annotations_
void p_scossl_set_core_bio(const OSSL_DISPATCH *dispatch)
{
    for (; dispatch->function_id != 0; dispatch++)
    {
        switch (dispatch->function_id)
        {
        case OSSL_FUNC_BIO_READ_EX:
            core_bio_read_ex = OSSL_FUNC_BIO_read_ex(dispatch);
            break;
        case OSSL_FUNC_BIO_WRITE_EX:
            core_bio_write_ex = OSSL_FUNC_BIO_write_ex(dispatch);
            break;
        case OSSL_FUNC_BIO_UP_REF:
            core_bio_up_ref = OSSL_FUNC_BIO_up_ref(dispatch);
            break;
        case OSSL_FUNC_BIO_FREE:
            core_bio_free = OSSL_FUNC_BIO_free(dispatch);
            break;
        case OSSL_FUNC_BIO_PUTS:
            core_bio_puts = OSSL_FUNC_BIO_puts(dispatch);
            break;
        case OSSL_FUNC_BIO_GETS:
            core_bio_gets = OSSL_FUNC_BIO_gets(dispatch);
            break;
        case OSSL_FUNC_BIO_CTRL:
            core_bio_ctrl = OSSL_FUNC_BIO_ctrl(dispatch);
            break;
        }
    }
}

BIO_METHOD *p_scossl_bio_init()
{
    BIO_METHOD *coreBioMeth = BIO_meth_new(BIO_TYPE_CORE_TO_PROV, "SCOSSL BIO to core filter");

    if (coreBioMeth != NULL &&
        (!BIO_meth_set_read_ex(coreBioMeth, p_scossl_bio_core_read_ex) ||
         !BIO_meth_set_write_ex(coreBioMeth, p_scossl_bio_core_write_ex) ||
         !BIO_meth_set_create(coreBioMeth, p_scossl_bio_core_create) ||
         !BIO_meth_set_destroy(coreBioMeth, p_scossl_bio_core_destroy) ||
         !BIO_meth_set_gets(coreBioMeth, p_scossl_bio_core_gets) ||
         !BIO_meth_set_puts(coreBioMeth, p_scossl_bio_core_puts) ||
         !BIO_meth_set_ctrl(coreBioMeth, p_scossl_bio_core_ctrl)))
    {
        BIO_meth_free(coreBioMeth);
        coreBioMeth = NULL;
    }

    return coreBioMeth;
}

_Use_decl_annotations_
BIO *p_scossl_bio_new_from_core_bio(SCOSSL_PROVCTX *provctx, OSSL_CORE_BIO *coreBio)
{
    BIO *bio;

    if (provctx == NULL || provctx->coreBioMeth == NULL)
    {
        return NULL;
    }

    if ((bio = BIO_new_ex(provctx->libctx, provctx->coreBioMeth)) != NULL)
    {
        if (core_bio_up_ref == NULL ||
            !core_bio_up_ref(coreBio))
        {
            BIO_free(bio);
            return NULL;
        }

        BIO_set_data(bio, coreBio);
    }

    return bio;
}

#ifdef __cplusplus
}
#endif