// This file includes definition of some of the lib functions from optee juno os.
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include "mbedtls/sha256.h"
#include "mbedtls/md_internal.h"
#define EMSG_ERR printk
#include "mbedtls/md5.h"
#define mbedtls_calloc    kzalloc
#define mbedtls_free       kfree

void raw_free(void *ptr)
{
	if (ptr)
		vfree(ptr);
}

void *raw_calloc(size_t hdr_size, size_t ftr_size, size_t pl_nmemb,
		size_t pl_size)
{
	size_t s = hdr_size + ftr_size + pl_nmemb * pl_size;
	void *ptr;

//	raw_malloc_validate_pools();

	/* Check wrapping */
	if (s < pl_nmemb || s < pl_size) {
		EMSG_ERR("%s failed\n", __func__);
		return NULL;
	}

	/* BGET doesn't like 0 sized allocations */
	if (!s)
		s++;

	ptr = vmalloc(s);
//	raw_malloc_save_max_alloced_size();

	return ptr;
}

//#if defined(MBEDTLS_SHA256_C)

static void sha224_starts_wrap( void *ctx )
{
    mbedtls_sha256_starts( (mbedtls_sha256_context *) ctx, 1 );
}

static void sha224_update_wrap( void *ctx, const unsigned char *input,
                                size_t ilen )
{
    mbedtls_sha256_update( (mbedtls_sha256_context *) ctx, input, ilen );
}

static void sha224_finish_wrap( void *ctx, unsigned char *output )
{
    mbedtls_sha256_finish( (mbedtls_sha256_context *) ctx, output );
}

static void sha224_wrap( const unsigned char *input, size_t ilen,
                    unsigned char *output )
{
    mbedtls_sha256( input, ilen, output, 1 );
}

mbedtls_sha256_context sha224_ctx;

static void *sha224_ctx_alloc( void )
{
    void *ctx = &sha224_ctx;

    if( ctx != NULL )
        mbedtls_sha256_init( (mbedtls_sha256_context *) ctx );

    return( ctx );
}

static void sha224_ctx_free( void *ctx )
{
    mbedtls_sha256_free( (mbedtls_sha256_context *) ctx );
}

static void sha224_clone_wrap( void *dst, const void *src )
{
    mbedtls_sha256_clone( (mbedtls_sha256_context *) dst,
                    (const mbedtls_sha256_context *) src );
}

static void sha224_process_wrap( void *ctx, const unsigned char *data )
{
    mbedtls_sha256_process( (mbedtls_sha256_context *) ctx, data );
}

const mbedtls_md_info_t mbedtls_sha224_info = {
    MBEDTLS_MD_SHA224,
    "SHA224",
    28,
    64,
    sha224_starts_wrap,
    sha224_update_wrap,
    sha224_finish_wrap,
    sha224_wrap,
    sha224_ctx_alloc,
    sha224_ctx_free,
    sha224_clone_wrap,
    sha224_process_wrap,
};

static void sha256_starts_wrap( void *ctx )
{
    mbedtls_sha256_starts( (mbedtls_sha256_context *) ctx, 0 );
}

static void sha256_wrap( const unsigned char *input, size_t ilen,
                    unsigned char *output )
{
    mbedtls_sha256( input, ilen, output, 0 );
}

const mbedtls_md_info_t mbedtls_sha256_info = {
    MBEDTLS_MD_SHA256,
    "SHA256",
    32,
    64,
    sha256_starts_wrap,
    sha224_update_wrap,
    sha224_finish_wrap,
    sha256_wrap,
    sha224_ctx_alloc,
    sha224_ctx_free,
    sha224_clone_wrap,
    sha224_process_wrap,
};

//#endif /* MBEDTLS_SHA256_C */

//#if defined(MBEDTLS_MD5_C)

static void md5_starts_wrap( void *ctx )
{
    mbedtls_md5_starts( (mbedtls_md5_context *) ctx );
}

static void md5_update_wrap( void *ctx, const unsigned char *input,
                             size_t ilen )
{
    mbedtls_md5_update( (mbedtls_md5_context *) ctx, input, ilen );
}

static void md5_finish_wrap( void *ctx, unsigned char *output )
{
    mbedtls_md5_finish( (mbedtls_md5_context *) ctx, output );
}

static void *md5_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_md5_context ) );

    if( ctx != NULL )
        mbedtls_md5_init( (mbedtls_md5_context *) ctx );

    return( ctx );
}

static void md5_ctx_free( void *ctx )
{
    mbedtls_md5_free( (mbedtls_md5_context *) ctx );
    mbedtls_free( ctx );
}

static void md5_clone_wrap( void *dst, const void *src )
{
    mbedtls_md5_clone( (mbedtls_md5_context *) dst,
                 (const mbedtls_md5_context *) src );
}

static void md5_process_wrap( void *ctx, const unsigned char *data )
{
    mbedtls_md5_process( (mbedtls_md5_context *) ctx, data );
}

const mbedtls_md_info_t mbedtls_md5_info = {
    MBEDTLS_MD_MD5,
    "MD5",
    16,
    64,
    md5_starts_wrap,
    md5_update_wrap,
    md5_finish_wrap,
    mbedtls_md5,
    md5_ctx_alloc,
    md5_ctx_free,
    md5_clone_wrap,
    md5_process_wrap,
};

//#endif /* MBEDTLS_MD5_C */

