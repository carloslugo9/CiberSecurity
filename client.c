/*****************************************************************************/
/*****************************************************************************/
/**************** I N C L U D E S   &   D E F I N I T I O N S ****************/
/*****************************************************************************/
/*****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* TCP/IP comm */
//#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 

#include "protocol_mngr.h"


/* Colors */
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



/*****************************************************************************/
/*****************************************************************************/
/********************* S T A T I C   P R O T O T Y P E S *********************/
/*****************************************************************************/
/*****************************************************************************/
static int sendDataTcp( int sockfd, unsigned char buff[], int size );
static int getDataTcp( int sockfd, unsigned char buff[] );
static void getConexParameters( int *entityId, int *portId, char serverIp[] );
static int comInit( int *sockfd, int portno, char serverIp[] );

/*****************************************************************************/
/*****************************************************************************/
/********************** P U B L I C   F U N C T I O N S **********************/
/*****************************************************************************/
/*****************************************************************************/
int main( int argc, char *argv[] )
{
    unsigned char TcpMessage[256], payload[32];
    int           TcpMessageSize, payloadSize;
    int           entityId = 3;
    char          keyboard[10];
    int           sockfd, portno = 8081;
    //char          serverIp[20] = "192.168.43.166";
    char          serverIp[20] = "192.168.15.10";
    
    printf(ANSI_COLOR_BOLD_GREEN);
    printf("**************************************************************\n");
    printf("************************ C L I E N T *************************\n");
    printf("**************************************************************\n\n");
    
    /* Getting info */
    printf(ANSI_COLOR_YELLOW);
    printf("> Getting connection parameters ... \n");
    printf(ANSI_COLOR_RESET);
    
    /* keyboard */
    getConexParameters(&entityId, &portno, serverIp);
    printf("  . Entity %d, Port %d, serverIp %s.\n", entityId, portno, serverIp);

    /* TCP */
    printf(ANSI_COLOR_YELLOW);
    printf("> Initializing communications ... ");
    fflush( stdout );
    printf(ANSI_COLOR_RESET);
    
    if(comInit(&sockfd , portno, serverIp) == 0)
        return 0;
        
    printf(ANSI_COLOR_YELLOW);
    printf("OK! Connected with server ");
    fflush( stdout );
    printf(ANSI_COLOR_RESET);
    

    while(1)
    {
        printf(ANSI_COLOR_YELLOW);
        printf("\n##################################################################");
        printf("\n> Write comand: #-val, donde #:");
        printf("\n> 1. Send message with \"val\" values ");
        printf("\n> 2. Send message with \"val\" values and altering sign ");
        printf("\n> 3. Send message with \"val\" values and altering AES key ");
        printf("\n> 4. Send message with \"val\" values and altering AES message ");
        printf("\n> 5. Send message with \"val\" values and altering hash: ");
        fflush( stdout );
        printf(ANSI_COLOR_RESET);
    
        /* Wait for keyboard command */
        memset( keyboard, 0, sizeof( keyboard ) );
        scanf("%s",keyboard);
        
        FromFileToMemory(&keyboard[2], &keyboard[2], 2);
        
        memset( TcpMessage, 0, sizeof( TcpMessage ) );
        
        memset( payload, keyboard[2], sizeof( payload ) );
        
        signAndCiphMessage(payload, sizeof(payload), TcpMessage, 
	   			           &TcpMessageSize, entityId);
        
        switch(keyboard[0])
        {
            /* Normal case, send<1-val> */
            case '1':                
                printf(ANSI_COLOR_YELLOW);
                printf("> Sending response...");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
                sendDataTcp(sockfd, TcpMessage, sizeof(TcpMessage)); 
                
                printf(ANSI_COLOR_YELLOW);
                printf("\n> Waiting for response...");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
                getDataTcp( sockfd, TcpMessage );
                VerifAndDecryptMessage(TcpMessage, payload, &payloadSize);
            break;
            
            /* Destroying signature */
            case '2':
                TcpMessage[37]++;
                
                printf(ANSI_COLOR_YELLOW);
                printf(  "> Altering signature (byte 41)...");
                printf("\n> New final message:  ");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
                
                dump_buf(  "", TcpMessage, TcpMessageSize );
                
                printf(ANSI_COLOR_YELLOW);
                printf("> Sending response... ");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
                
                sendDataTcp(sockfd, TcpMessage, sizeof(TcpMessage)); 
                
                printf(ANSI_COLOR_YELLOW);
                printf("OK!");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
            break;
            
            /* Destroying AES key */
            case '3':
                TcpMessage[100]++;
                
                printf(ANSI_COLOR_YELLOW);
                printf(  "> Altering AES key (byte 104)...");
                printf("\n> New final message:  ");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
                
                dump_buf(  "", TcpMessage, TcpMessageSize );
                
                printf(ANSI_COLOR_YELLOW);
                printf("> Sending response... ");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
                
                sendDataTcp(sockfd, TcpMessage, sizeof(TcpMessage)); 
                
                printf(ANSI_COLOR_YELLOW);
                printf("OK!");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
            break;
            
            /* Destroying AES encrypted msg */
            case '4':
                TcpMessage[130]++;
                
                printf(ANSI_COLOR_YELLOW);
                printf(  "> Altering AES encrypted msg (byte 134)...");
                printf("\n> New final message:  ");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
                
                dump_buf(  "", TcpMessage, TcpMessageSize );
                
                printf(ANSI_COLOR_YELLOW);
                printf("> Sending response... ");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
                
                sendDataTcp(sockfd, TcpMessage, sizeof(TcpMessage)); 
                
                printf(ANSI_COLOR_YELLOW);
                printf("OK!");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
            
            break;
            
            /* Destroying hash */
            case '5':
                TcpMessage[10]++;

                printf(ANSI_COLOR_YELLOW);
                printf(  "> Altering hash (byte 14)...");
                printf("\n> New final message:  ");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
                
                dump_buf(  "", TcpMessage, TcpMessageSize );
                
                printf(ANSI_COLOR_YELLOW);
                printf("> Sending response... ");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
                
                sendDataTcp(sockfd, TcpMessage, sizeof(TcpMessage)); 
                
                printf(ANSI_COLOR_YELLOW);
                printf("OK!");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
            
            break;
            
            default:
            break;
        }       
    }

	close( sockfd );

    return( 0 );
}


/*****************************************************************************/
/*****************************************************************************/
/********************** S T A T I C   F U N C T I O N S **********************/
/*****************************************************************************/
/*****************************************************************************/
static int comInit( int *sockfd, int portno, char serverIp[] )
{
    int retVal = 0;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    
    if ( ( *sockfd = socket(AF_INET, SOCK_STREAM, 0) ) < 0 )
        printf("\nERROR opening socket\n");

    if ( ( server = gethostbyname( serverIp ) ) == NULL ) 
        printf("\nERROR, no such host\n");

    bzero( (char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    
    bcopy( (char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(portno);
    
    if ( connect(*sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) 
    {
        printf(ANSI_COLOR_BOLD_RED);
        printf("\n> ERROR connecting\n");
        fflush( stdout );
        printf(ANSI_COLOR_RESET);
    }
    else
    {
        retVal = 1;
    }
        
    return retVal;
}


static int sendDataTcp( int sockfd, unsigned char buff[], int size ) 
{
  int n;
  if ( (n = write( sockfd, buff, size ) ) < 0 )
	printf("\nERROR writing to socket\n");
	
    return n;
}


static int getDataTcp( int sockfd, unsigned char buff[] ) {

  int n;

  if ( (n = read(sockfd,buff,256) ) < 0 )
        printf("\nERROR reading from socket\n");
        

  return n;
}


static void getConexParameters( int *entityId, int *portId, char serverIp[])
{
    char keyboard[100];
    char entity[2];
    char port[5];
    int ctr;

    printf(  "  . Current entity: %d (can be 0-4)", *entityId);    
    printf("\n  . Current port:   %d (most be size 4)", *portId);
    printf("\n  . Current ip:     %s", serverIp);
    printf("\n  . To change first type entity then port and final ip.");
    printf("\n  . Eg: <2-8081-XXX.XXX.XXX.XXX>. If not type <c>");
    printf("\n  . <");
    
    scanf("%s",keyboard);

    if(keyboard[0] != 'c' )
    {
        entity[0] = keyboard[0];
        entity[1] = '\n';
        *entityId = atoi((const char *)entity);
        
        port[0] = keyboard[2];
        port[1] = keyboard[3];
        port[2] = keyboard[4];
        port[3] = keyboard[5];
        port[4] = '\n';
        *portId = atoi((const char *)port);
        
        memset(serverIp, 0x00, 20);
        
        for(ctr = 7; ctr < 30 ; ctr++)
        {   
            if( '>' == keyboard[ctr] )
                break;
                
            serverIp[ctr-7] = keyboard[ctr]; 
        }
        
        fflush( stdout );   
    }
}


