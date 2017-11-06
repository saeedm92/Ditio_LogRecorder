/*
 * Ditio Enryption and signing APIs
 * File: entry_fast.c
 *
 * Copyright (c) 2017 University of California, Irvine, CA, USA
 * All rights reserved.
 *
 * Authors: Saeed Mirzamohammadi <saeed@uci.edu>
 * Ardalan Amiri Sani   <arrdalan@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>. 
 *
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include "entry_fast.h"
#include <linux/string.h>
#include "mbed_lib/mbedtls/aes.h"
#include "mbed_lib/mbedtls/entropy.h"
#include "mbed_lib/mbedtls/ctr_drbg.h"
#include "mbed_lib/mbedtls/rsa.h"
#include "mbed_lib/mbedtls/bignum.h"
#include "mbed_lib/mbedtls/md.h"
#include "mbed_lib/mbedtls/oid.h"
#include "mbed_lib/mbedtls/sha256.h" 
#include "rsa_key/rsa_enc_pub.h"
#include "rsa_key/rsa_sign_priv.h"

static unsigned char aes_key[16] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
uint8_t shared_buf[10000];
uint64_t current_id = 0;
int es_ret;
mbedtls_rsa_context rsa_enc, rsa_sign;
mbedtls_entropy_context es_entropy;
mbedtls_ctr_drbg_context es_ctr_drbg;
unsigned char buf2[256];
unsigned char hash[32];
unsigned char input_key[16];
unsigned char encrypted_key[256];
const char *es_pers = "rsa_encrypt";

#define EMSG1 printk

uint32_t encrypt_and_sign(void)
{
        EMSG1("Begin getting key\n");
        /* ENCRYPT AES KEY */
        mbedtls_ctr_drbg_init( &es_ctr_drbg );
        es_ret = 1;

        mbedtls_entropy_init( &es_entropy );
        if( ( es_ret = mbedtls_ctr_drbg_seed( &es_ctr_drbg, mbedtls_entropy_func,
        &es_entropy, (const unsigned char *) es_pers, strlen( es_pers ) ) ) != 0 )
        {
                goto exit;
        }
        mbedtls_rsa_init( &rsa_enc, MBEDTLS_RSA_PKCS_V15, 0 );
        if( ( es_ret = mbedtls_mpi_read_string( &rsa_enc.N, 16, KEY_EN_PUB_N ) ) != 0
        || ( es_ret = mbedtls_mpi_read_string( &rsa_enc.E, 16, KEY_EN_PUB_E ) ) != 0 )
        {
                goto exit_rsa1;
        }
        rsa_enc.len = ( mbedtls_mpi_bitlen( &rsa_enc.N ) + 7 ) >> 3;

        memcpy(input_key, aes_key, 16);
        /*
         * Calculate the RSA encryption of the hash.
        */
        if( ( es_ret = mbedtls_rsa_pkcs1_encrypt( &rsa_enc, mbedtls_ctr_drbg_random,
        &es_ctr_drbg, MBEDTLS_RSA_PUBLIC, 16, input_key, encrypted_key ) ) != 0 )
        {
                goto exit_rsa1;
        }

        EMSG1("key encrypted \n");
        /* SIGN ENCRYPTED KEY */
        mbedtls_rsa_init( &rsa_sign, MBEDTLS_RSA_PKCS_V15, 0 );
        if( ( es_ret = mbedtls_mpi_read_string( &rsa_sign.N , 16, KEY_SI_PRIV_N ) ) != 0 ||
        ( es_ret = mbedtls_mpi_read_string( &rsa_sign.E , 16, KEY_SI_PRIV_E ) ) != 0 ||
        ( es_ret = mbedtls_mpi_read_string( &rsa_sign.D , 16, KEY_SI_PRIV_D ) ) != 0 ||
        ( es_ret = mbedtls_mpi_read_string( &rsa_sign.P , 16, KEY_SI_PRIV_P ) ) != 0 ||
        ( es_ret = mbedtls_mpi_read_string( &rsa_sign.Q , 16, KEY_SI_PRIV_Q ) ) != 0 ||
        ( es_ret = mbedtls_mpi_read_string( &rsa_sign.DP, 16, KEY_SI_PRIV_DP ) ) != 0 ||
        ( es_ret = mbedtls_mpi_read_string( &rsa_sign.DQ, 16, KEY_SI_PRIV_DQ ) ) != 0 ||
        ( es_ret = mbedtls_mpi_read_string( &rsa_sign.QP, 16, KEY_SI_PRIV_QP ) ) != 0 )
        {
                goto exit_rsa2;
        }
        rsa_sign.len = ( mbedtls_mpi_bitlen( &rsa_sign.N ) + 7 ) >> 3;

        EMSG1("priv key inited \n");
        /*  
         * Compute the SHA-256 hash of the input file,
         * then calculate the RSA signature of the hash.
        */

        if( ( es_ret = mbedtls_md( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                encrypted_key, rsa_enc.len, hash ) ) != 0 )
        {
                goto exit_rsa2;
        }
        EMSG1("got hash \n");

        if( ( es_ret = mbedtls_rsa_pkcs1_sign( &rsa_sign, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256,
                                20, hash, buf2 ) ) != 0 )
        {
                goto exit_rsa2;
        }
        EMSG1("signed hash \n");
        /* copy keys */
        memcpy(shared_buf, encrypted_key, 256);
        memcpy(shared_buf + 256, buf2, 256);

exit_rsa2:
	mbedtls_rsa_free( &rsa_sign );
exit_rsa1:
	mbedtls_rsa_free( &rsa_enc );
exit:
        mbedtls_ctr_drbg_free( &es_ctr_drbg );
        mbedtls_entropy_free( &es_entropy );

        return( es_ret );
}

unsigned char ic_key[16];
mbedtls_ctr_drbg_context ic_ctr_drbg;
mbedtls_entropy_context ic_entropy;

uint32_t initialize_connection(void)
{
        char *pers = "aes generate key";
        int ret;

        mbedtls_entropy_init( &ic_entropy );
        if( ( ret = mbedtls_ctr_drbg_seed( &ic_ctr_drbg, mbedtls_entropy_func, &ic_entropy,
        (unsigned char *) pers, strlen( pers ) ) ) != 0 )
        {
                goto exit;
        }

        if( ( ret = mbedtls_ctr_drbg_random( &ic_ctr_drbg, ic_key, 16 ) ) != 0 )
        {
                goto exit;
        }

        /* Copy aes_key */
        memcpy(aes_key, ic_key, 16);

        EMSG1("AES KEY: ");

exit:
        return ret; 

}

unsigned char sb_iv[16];
unsigned char *sb_input = NULL;
unsigned char *sb_output = NULL;
unsigned char sb_hmac[32];
mbedtls_rsa_context rsa_sig_buf;
mbedtls_aes_context sb_aes;

uint32_t sign_buf(void)
{
        int input_len = 8144;
        int ret, i;
	uint64_t unique = 567;

	if (!sb_output)
		sb_output = kmalloc(8192 * sizeof(unsigned char), GFP_KERNEL);
	if (!sb_input)
		sb_input = kmalloc(8192 * sizeof(unsigned char), GFP_KERNEL);

	if (!sb_output || !sb_input) {
		EMSG1("Error: Could not allocate memory\n");
		return -1;
	}


	for (i = 0; i < 16; i++)
		sb_iv[i] = i;

	for (i = 0; i < 16; i++)
		EMSG1("Key: %d", aes_key[i]);
        EMSG1("Encrypting begin\n");
	memcpy(sb_input, shared_buf, 8144);
        /* Encrypt the data */
        ret = mbedtls_aes_setkey_enc( &sb_aes, aes_key, 128 );
        if (ret) {
                goto err; 
        }
        ret = mbedtls_aes_crypt_cbc( &sb_aes, MBEDTLS_AES_ENCRYPT, input_len,
                                        sb_iv, sb_input, sb_output );
        if (ret) {
                goto err; 
        }
	memcpy(shared_buf, sb_output, 8144);

	ret = mbedtls_md_hmac( mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
			aes_key, 16, shared_buf, 8144, sb_hmac);
	if (ret) {
		EMSG1("Could not get HMAC\n");
		goto err;
	}
	memcpy((shared_buf + 8144), sb_hmac, 32);
	memcpy((shared_buf + 8176), &unique, 8);

	EMSG1("Set HMAC to end of buffer\n");
err:
        return 0;
}
unsigned char dt_iv[16];
unsigned char dt_input [32];
unsigned char dt_output[32];
mbedtls_aes_context dt_aes;

uint32_t decrypt_time(void)
{
        int input_len = 32;
        int ret, i;

	for (i = 0; i < 16; i++)
		dt_iv[i] = 0;
        EMSG1("Decrypting begin\n");
        memcpy(dt_input, shared_buf, 32);

        /* Encrypt the data */
        ret = mbedtls_aes_setkey_dec( &dt_aes, aes_key, 128 );
        if (ret) {
                goto err;
        }
        // Decrypting buffer
        ret = mbedtls_aes_crypt_cbc( &dt_aes, MBEDTLS_AES_DECRYPT, input_len,
                                                dt_iv, dt_input, dt_output );
        if (ret) {
                goto err;
        }
	current_id = ((uint64_t *)dt_output)[1];

        memcpy(shared_buf, dt_output, 8);
err:
        return 0;
}
