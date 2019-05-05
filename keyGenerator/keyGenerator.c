#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_ECDSA_C) && \
    defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"

#include <string.h>
#endif


/*
 * Uncomment to show key and signature details
 */
#define VERBOSE

/*
 * Uncomment to force use of a specific curve
 */
#define ECPARAMS    MBEDTLS_ECP_DP_SECP192R1

#if !defined(ECPARAMS)
#define ECPARAMS    mbedtls_ecp_curve_list()->grp_id
#endif

#if !defined(MBEDTLS_ECDSA_C) || !defined(MBEDTLS_SHA256_C) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{#include "mbedtls/sha256.h"
    mbedtls_printf("MBEDTLS_ECDSA_C and/or MBEDTLS_SHA256_C and/or "
           "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C not defined\n");
    return( 0 );
}
#else
#if defined(VERBOSE)

#else
#define dump_buf( a, b, c )
#define dump_pubkey( a, b )
#endif

#if defined(MBEDTLS_CHECK_PARAMS)
#include "mbedtls/platform_util.h"
void mbedtls_param_failed( const char *failure_condition,
                           const char *file,
                           int line )
{
    mbedtls_printf( "%s:%i: Input param failed - %s\n",ctx_sign
                    file, line, failure_condition );
    mbedtls_exit( MBEDTLS_EXIT_FAILURE );
}
#endif

#define NUM_OF_PAIR_KEYS  5U


int main( int argc, char *argv[] )
{
    /*  V A R I A B L E S  */
    int exit_code = MBEDTLS_EXIT_FAILURE;
    const char *pers = "ecdsa";			/* custom data */
    
    ((void) argv);				/* Argument casting */
    int ret = 1;
    
    FILE *fp, *fpdb;
    char filename[] = "key_0.txt";
    int ctr;
    int ctx_ctr;

    mbedtls_ecdsa_context    ctx_sign[NUM_OF_PAIR_KEYS];  	/* To sign message */
    mbedtls_ctr_drbg_context ctr_drbg[NUM_OF_PAIR_KEYS];	/* Counter mode Deterministic Random Byte Generator */
    mbedtls_entropy_context  entropy[NUM_OF_PAIR_KEYS];

    fpdb = fopen ("key_database.txt","w");
    
    if(fpdb == NULL)
    {
        printf("\n\n\tError openning file!\n");
        while(1);
    }

    for(ctx_ctr = 0 ; ctx_ctr < NUM_OF_PAIR_KEYS ; ctx_ctr++)
    {
    	mbedtls_printf( "\n  . Key num [%d]",ctx_ctr );
    	
    	/*  I N I T I A L I Z A T I O N  */
	    /* contexts */
	    mbedtls_ecdsa_init( &ctx_sign[ctx_ctr] );		/* Init context for signing */
	    mbedtls_ctr_drbg_init( &ctr_drbg[ctx_ctr] );		/* Init random generator */

	    /*
	    * Generate a key pair for signing
	    */
	    mbedtls_printf( "\n  . Seeding the random number generator..." );
	    fflush( stdout );

	    mbedtls_entropy_init( &entropy[ctx_ctr] );				/* Entropy for DRBG */

	    /* random generator (input = entropy) */
	    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg[ctx_ctr], 			/* Random context to generate */
					       mbedtls_entropy_func, 		/* cbk */
					       &entropy[ctx_ctr],			/* entopy input */
		                   		   (const unsigned char *) pers,	/* custom data ("ecdsa") */
		                   		   strlen( pers ) )			/* custom data length */
				          ) != 0 )
	    {
	        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
	        goto exit;
	    }

	    mbedtls_printf( " ok\n  . Generating key pair..." );
	    fflush( stdout );

	    /* key gen (input = DRBG context ) */
	    /* This function generates an ECDSA keypair on the given curve.  */
	    if( ( ret = mbedtls_ecdsa_genkey(   &ctx_sign[ctx_ctr], 		/* The ECDSA context to store the keypair in. */
					                        ECPARAMS,			        /* The elliptic curve to use */
		                  		            mbedtls_ctr_drbg_random,	/* The RNG function to use (f_rng) */
					                        &ctr_drbg[ctx_ctr] )		/* The RNG context to be passed to f_rng */
				            ) != 0 )
	    {
	        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret );
	        goto exit;
	    }

	    mbedtls_printf( " ok (key size: %d bits)", (int) ctx_sign[ctx_ctr].grp.pbits );

	    /************* Printing keys **************/
	    fp = fopen ((const char *)&filename,"w");
	    
        if(fp == NULL)
        {
            printf("\n\n\tError openning file 2!\n");
            while(1);
        }

        size_t sizeOut = 0;
        unsigned char buff2Print[100];
        
        /* ctx_sign.grp */
        mbedtls_ecp_tls_write_group(&ctx_sign[ctx_ctr].grp, &sizeOut, buff2Print, 100);
        for(ctr = 0 ; ctr < sizeOut ; ctr++)
        {
		    fprintf (fp,   "%02X",buff2Print[ctr]);
		    fprintf (fpdb, "%02X",buff2Print[ctr]);
		}
    
        fprintf (fp, "\n");
        fprintf (fpdb, "\n");
		mbedtls_printf( "\n  . Group len:%ld",sizeOut);
		
		/* ctx_sign.d */
        mbedtls_ecp_tls_write_point(   &ctx_sign[ctx_ctr].grp, (const mbedtls_ecp_point *)&ctx_sign[ctx_ctr].d,
                                       MBEDTLS_ECP_PF_UNCOMPRESSED, &sizeOut, buff2Print, 100);

        for(ctr = 0 ; ctr < sizeOut ; ctr++)
        {
		    fprintf (fp,   "%02X",buff2Print[ctr]);
		    fprintf (fpdb, "00");
		}
		
        fprintf (fp, "\n");
        fprintf (fpdb, "\n");
		mbedtls_printf( "\n  . Private buffer len:%ld",sizeOut);
		
        /* ctx_sign.Q */
        mbedtls_ecp_tls_write_point(   &ctx_sign[ctx_ctr].grp, &ctx_sign[ctx_ctr].Q,
                                       MBEDTLS_ECP_PF_UNCOMPRESSED, &sizeOut, buff2Print, 100);
  
        for(ctr = 0 ; ctr < sizeOut ; ctr++)
        {
		    fprintf (fp,   "%02X",buff2Print[ctr]);
		    fprintf (fpdb, "%02X",buff2Print[ctr]);
		}
		
		fprintf (fpdb, "\n");
		
		mbedtls_printf( "\n  . Public buffer len:%ld\n",sizeOut);
		
        fclose (fp);
        
  	    filename[4]++; // File ID
    }

    fclose (fpdb);

exit:

    return( exit_code );
}


#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C &&
          ECPARAMS */
