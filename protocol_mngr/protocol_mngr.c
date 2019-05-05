/*****************************************************************************/
/*****************************************************************************/
/**************** I N C L U D E S   &   D E F I N I T I O N S ****************/
/*****************************************************************************/
/*****************************************************************************/
#include "protocol_mngr.h"
#define MAXCHAR 1000

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
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"

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

#define ANSI_COLOR_BOLD_GREEN   "\033[1;32m"
#define ANSI_COLOR_BOLD_RED     "\033[1;31m"
#define ANSI_COLOR_YELLOW       "\033[1;33m"

#define ANSI_COLOR_RED          "\x1b[31m"
#define ANSI_COLOR_GREEN        "\x1b[32m"
#define ANSI_COLOR_BLUE         "\x1b[34m"
#define ANSI_COLOR_MAGENTA      "\x1b[35m"
#define ANSI_COLOR_CYAN         "\x1b[36m"
#define ANSI_COLOR_RESET        "\033[0m"

/*****************************************************************************/
/*****************************************************************************/
/********************** S T A T I C   V A R I A B L E S **********************/
/*****************************************************************************/
/*****************************************************************************/
const static unsigned char IV[16] = 
{       
    0x10,0x14,0xAA,0xC7,0xD5,0xAA,0xDD,0xF4,
    0x66,0x10,0x15,0x45,0x0A,0xBB,0x48,0x18
};

static mbedtls_ecdsa_context ctx_Mysign;  	/* To sign message */
static mbedtls_ecdsa_context ctx_sign_Db[5];


/*****************************************************************************/
/*****************************************************************************/
/********************* S T A T I C   P R O T O T Y P E S *********************/
/*****************************************************************************/
/*****************************************************************************/
static void FromFileToMemory(char *src, char *dst, int len);
static void dump_privkey( const char *title, mbedtls_ecdsa_context *key );
static void dump_pubkey( const char *title, mbedtls_ecdsa_context *key );


/*****************************************************************************/
/*****************************************************************************/
/********************** P U B L I C   F U N C T I O N S **********************/
/*****************************************************************************/
/*****************************************************************************/
void getMyKeys( void )
{
    FILE *fp;
    char str[MAXCHAR];
    int selector = 0;
    const unsigned char *bufGrpPointer;

    fp = fopen("keyGenerator//key_3.txt", "r");
   
    while (fgets(str, MAXCHAR, fp) != NULL)
    {
        switch(selector)
        {
            case 0:
            FromFileToMemory(str, str, 10 );
            bufGrpPointer = (const unsigned char *)&str[0];
            mbedtls_ecp_tls_read_group(&ctx_Mysign.grp,&bufGrpPointer,MAXCHAR);
            selector = 1;
            break;
            
            case 1:
            FromFileToMemory(str, str, 200 );
            bufGrpPointer = (const unsigned char *)&str[0];
            mbedtls_ecp_tls_read_point( &ctx_Mysign.grp,(mbedtls_ecp_point *)&ctx_Mysign.d,
                                        &bufGrpPointer, MAXCHAR);
            selector = 2;
            break;
            
            case 2:
            FromFileToMemory(str, str, 200 );
            bufGrpPointer = (const unsigned char *)&str[0];
            mbedtls_ecp_tls_read_point( &ctx_Mysign.grp, &ctx_Mysign.Q,&bufGrpPointer, MAXCHAR);
            selector = 3;
            break;
        }
    }
    
    fclose(fp);

    dump_privkey( "My Priv key:   ", &ctx_Mysign );
    dump_pubkey(  "My Public key: ", &ctx_Mysign );       
}


void geyKeyDatabase( void )
{
    /* READ DB */
    FILE *fpDb;
    char str[MAXCHAR];
    int dbCtr    = 0;
    int selector = 0;
    const unsigned char *bufGrpPointer;

    fpDb = fopen("keyGenerator//key_database.txt", "r");   

    while (fgets(str, MAXCHAR, fpDb) != NULL)
    {
        switch(selector)
        {
            case 0:
            FromFileToMemory(str, str, 10 );
            bufGrpPointer = (const unsigned char *)&str[0];
            mbedtls_ecp_tls_read_group(&ctx_sign_Db[dbCtr].grp,&bufGrpPointer,MAXCHAR);
            selector = 1;
            break;
            
            case 1:
            FromFileToMemory(str, str, 100 );
            bufGrpPointer = (const unsigned char *)&str[0];
            mbedtls_ecp_tls_read_point( &ctx_sign_Db[dbCtr].grp,(mbedtls_ecp_point *)&ctx_sign_Db[dbCtr].d,
                                        &bufGrpPointer, MAXCHAR);
            selector = 2;
            break;
            
            case 2:
            FromFileToMemory(str, str, 100 );
            bufGrpPointer = (const unsigned char *)&str[0];
            mbedtls_ecp_tls_read_point( &ctx_sign_Db[dbCtr].grp, &ctx_sign_Db[dbCtr].Q,&bufGrpPointer, MAXCHAR);
            selector = 0;
            
            printf("Public key[%d]: ",dbCtr);
            dump_pubkey( "", &ctx_sign_Db[dbCtr] );   

            dbCtr++;
            break;
        }
    }

    fclose(fpDb);
}

void signAndCiphMessage( unsigned char payload[], 
	                              int  payloadSize,
			             unsigned char tcpMessage[],
  			                      int  *tcpMsgSize )
{
    unsigned char hash[32];
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];	/* L = 139 */
    size_t sig_len;
    int ret;
    mbedtls_ctr_drbg_context ctr_drbg;	
    mbedtls_entropy_context entropy;
    const char *pers = "ecdsa";			/* custom data */
    /* AES */
    mbedtls_aes_context aes_ctx;
    unsigned char key[32];
    unsigned char IV_cpy[16];
    unsigned char bufferOutAes[32];
    
    /* Compute message hash */
    mbedtls_printf( "\n  . Hashing message..." );

    mbedtls_sha256_ret( payload,		    /* Buffer holding data */
	                    payloadSize, 	    /* length */
	                    hash,		        /* Hash buffer (32 bytes) */
                        0); 	            /* 0 for SHA-256, or 1 for SHA-224. */

    mbedtls_printf( " ok" );
    dump_buf( "\n  . Hash: ", hash, sizeof( hash ) );
    printf(     "  . Hash length: %ld", sizeof( hash ) );
    
    mbedtls_printf( "\n  . Signing message..." );
    
    /* Calculating entropy */
    mbedtls_ctr_drbg_init( &ctr_drbg );	
    mbedtls_entropy_init( &entropy ); 					/* Entropy for DRBG */

    if( ( ret = mbedtls_ctr_drbg_seed( 	&ctr_drbg, 			            /* Random context to generate */
					                    mbedtls_entropy_func, 		    /* cbk */
					                    &entropy,			            /* entopy input */
                               		    (const unsigned char *) pers,	/* custom data ("ecdsa") */
                               		    strlen( pers ) )		        /* custom data length */
				                     ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
    }

    /* Signing message */
    if( ( ret = mbedtls_ecdsa_write_signature(  &ctx_Mysign, 		     /* ECDSA context  */
						                        MBEDTLS_MD_SHA256,	     /* Hash algorithm */
                                       		    hash,			         /* Messahe hash */
						                        sizeof( hash ),		     /* Lenght of hash */
                               			        sig,			         /* Buffer will hold signature */
						                        &sig_len,		         /* Signature length */
                                       		    mbedtls_ctr_drbg_random, /* RNG function */
						                        &ctr_drbg		         /* RNG parameter */
					                         ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret );
    }
    
    dump_buf(  " ok\n  . Signature: ", sig, sig_len );
    mbedtls_printf( "  . Signature length = %u", (unsigned int) sig_len );
    
    /* AES */
    printf("\n  . Applying AES encript algorithm...");
 
    /* Init ctx */
    mbedtls_aes_init( &aes_ctx );
    
    /* Set buffers */
    memcpy(IV_cpy, IV, sizeof( IV_cpy ));
    memset( bufferOutAes, 	0, sizeof( bufferOutAes ) );

    /* Generate random key value */
    memset( key, 0, sizeof( key ) );
    
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
    (unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret );
    }

    if( ( ret = mbedtls_ctr_drbg_random( &ctr_drbg, key, 32 ) ) != 0 )
    {
        printf( " failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret );
    }
    
    dump_buf("\n  . Key:  ",key,sizeof(key));
    printf(     "  . Key length: %ld", sizeof( key ) );
    
    /* Set key */
    mbedtls_aes_setkey_enc( &aes_ctx, key, 256 );
    
    /* Apply algorithm */
    mbedtls_aes_crypt_cbc( &aes_ctx, MBEDTLS_AES_ENCRYPT, sizeof(bufferOutAes), IV_cpy, payload, bufferOutAes );
    dump_buf("\n  . Encrypted message: ",bufferOutAes,sizeof(bufferOutAes));
    printf(  "  . Encrypted message length: %ld", sizeof( bufferOutAes ) );

    /* Preapre whole message */
    *tcpMsgSize = 4 + sizeof( hash ) + sig_len + sizeof( key ) + sizeof( bufferOutAes );
    printf("\n  . Prepararing whole message of size:%d ...", *tcpMsgSize);

    tcpMessage[0] = sizeof( hash );
    tcpMessage[1] = sig_len;
    tcpMessage[2] = sizeof( key );
    tcpMessage[3] = sizeof( bufferOutAes );
    
    memcpy(&tcpMessage[4],                                             hash,         sizeof( hash ));
    memcpy(&tcpMessage[4 + sizeof( hash ) ],                           sig,          sig_len);
    memcpy(&tcpMessage[4 + sizeof( hash ) + sig_len ],                 key,          sizeof( key ));
    memcpy(&tcpMessage[4 + sizeof( hash ) + sig_len + sizeof( key ) ], bufferOutAes, sizeof( bufferOutAes ));
    
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    
    dump_buf("\n  . Final message is: ",tcpMessage,*tcpMsgSize);
}


int VerifAndDecryptMessage(unsigned char tcpMessage[],
								     int  tcpMsgSize,
							unsigned char payload[],
									 int  *payloadSize)
{
    unsigned char hash[32], hash_ver[32];
    int hashSize;
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];	/* L = 139 */
    size_t sig_len;
    int ret, returnVal = 0;
    /* AES */
    mbedtls_aes_context aes_ctx;
    unsigned char key[32];
    int keySize;
    unsigned char IV_cpy[16];
    unsigned char bufferInAes[32];
    int ctx_ctr = 0, match_flag = 100;
    
    /* Starting message verification */
    mbedtls_printf( "\n  . Starting verification..." );
    hashSize      = tcpMessage[0];
    sig_len       = tcpMessage[1];
    keySize       = tcpMessage[2];
    *payloadSize  = tcpMessage[3];
    
    memcpy(hash,         &tcpMessage[4],                                hashSize);
    memcpy(sig,          &tcpMessage[4 + hashSize],                     sig_len);
    memcpy(key,          &tcpMessage[4 + hashSize + sig_len ],          keySize);
    memcpy(bufferInAes,  &tcpMessage[4 + hashSize + sig_len + keySize], *payloadSize);
    
    dump_buf(  "\n  . The signature: ", sig, sig_len );
        
    for(ctx_ctr = 0; ctx_ctr < 5 ; ctx_ctr++)
    {
        if( ( ret = mbedtls_ecdsa_read_signature( &ctx_sign_Db[ctx_ctr],
                                                  hash, hashSize,
                                                  sig, sig_len ) ) != 0 )
        {
            printf("  . Does not match with <%d> entity\n", ctx_ctr);
        }
        else
        {
            printf("  . > Found. Match with <%d> entity!!!\n", ctx_ctr);
            match_flag = ctx_ctr;
        }
    }
    

    if(match_flag != 100)
    {
        printf(ANSI_COLOR_BOLD_GREEN);
        printf("  . Verification OK!!!");
        printf(ANSI_COLOR_RESET);
        
        printf("\n  . Applying AES dencript algorithm...\n");
        dump_buf(  "  . The key:        ", key, keySize );
        dump_buf(  "  . And encryp msg: ", bufferInAes, *payloadSize );

        /* AES */
        mbedtls_aes_init( &aes_ctx );
        memset( payload, 0x00, *payloadSize );
        memcpy(IV_cpy, IV, sizeof( IV_cpy ));
        
        mbedtls_aes_setkey_dec( &aes_ctx, key, 256 );
        mbedtls_aes_crypt_cbc( &aes_ctx, MBEDTLS_AES_DECRYPT, *payloadSize, IV_cpy, bufferInAes,  payload );
        printf(ANSI_COLOR_BOLD_GREEN);
        dump_buf(  "  . Generates msg:  ", payload, *payloadSize );
        printf(ANSI_COLOR_RESET);
        
        /* Hash */
        printf("  . Applying hash to corroborate data integrity...\n");
        dump_buf("  . Hash received:   ", hash, hashSize  );
        memset( hash_ver, 0x00, sizeof(hash_ver) );
        
        /* Compute message hash */
        mbedtls_sha256_ret( payload,		    /* Buffer holding data */
	                        *payloadSize, 	    /* length */
	                        hash_ver,           /* Hash buffer (32 bytes) */
                            0); 	            /* 0 for SHA-256, or 1 for SHA-224. */

        dump_buf( "  . Hash calculated: ", hash_ver, sizeof( hash_ver ) );
        
        if(0 == memcmp(hash, hash_ver, hashSize))
        {
            returnVal = 1;
            printf(ANSI_COLOR_BOLD_GREEN);
            printf("  . Data integity Ok!!!\n");
            printf(ANSI_COLOR_RESET);
        }
        else
        {
            printf(ANSI_COLOR_BOLD_RED);
            printf("  . Data is corrupted!!!\n");
            printf(ANSI_COLOR_RESET);
        }   
    }
    else
    {
        printf(ANSI_COLOR_BOLD_RED);
        printf("  . Verification fail!!!");
        printf(ANSI_COLOR_RESET);
    }

    return returnVal;
}


void dump_buf( const char *title, unsigned char *buf, size_t len )
{
    size_t i;

    mbedtls_printf( "%s", title );
    for( i = 0; i < len; i++ )
    {
        mbedtls_printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16] );
    }

    mbedtls_printf( "\n" );
}

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


/*****************************************************************************/
/*****************************************************************************/
/********************** S T A T I C   F U N C T I O N S **********************/
/*****************************************************************************/
/*****************************************************************************/
static void FromFileToMemory(char *src, char *dst, int len)
{
    int ctrWord;
    int ctrByte = 0;
    
    for(ctrWord = 0 ; ctrWord < len ; ctrWord += 2)
    {
        char temp = 0;
        
        switch(src[ctrWord + 1])
        {
            case '0': temp = 0x00; break;
            case '1': temp = 0x01; break;
            case '2': temp = 0x02; break;
            case '3': temp = 0x03; break;
            case '4': temp = 0x04; break;
            case '5': temp = 0x05; break;
            case '6': temp = 0x06; break;
            case '7': temp = 0x07; break;
            case '8': temp = 0x08; break;
            case '9': temp = 0x09; break;
            case 'A': temp = 0x0A; break;
            case 'B': temp = 0x0B; break;
            case 'C': temp = 0x0C; break;
            case 'D': temp = 0x0D; break;
            case 'E': temp = 0x0E; break;
            case 'F': temp = 0x0F; break;
        }
        
        switch(src[ctrWord])
        {
            case '0': temp |= 0x00; break;
            case '1': temp |= 0x10; break;
            case '2': temp |= 0x20; break;
            case '3': temp |= 0x30; break;
            case '4': temp |= 0x40; break;
            case '5': temp |= 0x50; break;
            case '6': temp |= 0x60; break;
            case '7': temp |= 0x70; break;
            case '8': temp |= 0x80; break;
            case '9': temp |= 0x90; break;
            case 'A': temp |= 0xA0; break;
            case 'B': temp |= 0xB0; break;
            case 'C': temp |= 0xC0; break;
            case 'D': temp |= 0xD0; break;
            case 'E': temp |= 0xE0; break;
            case 'F': temp |= 0xF0; break;
        }
        
        dst[ctrByte++] = temp;    
    }
}

#if !defined(MBEDTLS_ECDSA_C) || !defined(MBEDTLS_SHA256_C) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_ECDSA_C and/or MBEDTLS_SHA256_C and/or "
           "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C not defined\n");
    return( 0 );
}
#else
#if defined(VERBOSE)

static void dump_pubkey( const char *title, mbedtls_ecdsa_context *key )
{
    unsigned char buf[300];
    size_t len;

    if( mbedtls_ecp_point_write_binary( &key->grp, &key->Q,
                MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf ) != 0 )
    {
        mbedtls_printf("internal error\n");
        return;
    }

    dump_buf( title, buf, len );
}

static void dump_privkey( const char *title, mbedtls_ecdsa_context *key )
{
    unsigned char buf[300];
    size_t len;

    if( mbedtls_ecp_point_write_binary( &key->grp, (const mbedtls_ecp_point *)&key->d,
                MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf ) != 0 )
    {
        mbedtls_printf("internal error\n");
        return;
    }

    dump_buf( title, buf, len );
}

#else
#define dump_buf( a, b, c )
#define dump_pubkey( a, b )
#endif

#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C &&
          ECPARAMS */
