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
static int clilen, sockfd;
static struct sockaddr_in serv_addr, cli_addr;


/*****************************************************************************/
/*****************************************************************************/
/********************* S T A T I C   P R O T O T Y P E S *********************/
/*****************************************************************************/
/*****************************************************************************/
static int  sendDataTcp( int sockfd, unsigned char buff[], int size );
static int  getDataTcp( int sockfd, unsigned char buff[] );
static int  comInit(int portno);
static int  startCom(int *newsockfd);
static void getConexParameters( int *entityId, int *portId );

/*****************************************************************************/
/*****************************************************************************/
/********************** P U B L I C   F U N C T I O N S **********************/
/*****************************************************************************/
/*****************************************************************************/
int main( int argc, char *argv[] )
{
    unsigned char TcpMessage[200], payload[32];
    int           TcpMessageSize,  payloadSize;
    int           entityId = 0, char2send = 0;
    int           newsockfd, portno = 8081;
    
    /* Welcome screen */
    printf(ANSI_COLOR_BOLD_GREEN);
    printf("**************************************************************\n");
    printf("************************* S E R V E R ************************\n");
    printf("**************************************************************\n\n");

    /* Getting info */
    printf(ANSI_COLOR_YELLOW);
    printf("> Getting connection parameters ... \n");
    printf(ANSI_COLOR_RESET);
    
    /* keyboard */
    getConexParameters(&entityId, &portno);
    printf("  . Entity %d, Port %d\n", entityId, portno);

    /* TCP */
    printf(ANSI_COLOR_YELLOW);
    printf("> Initializing communications ... ");
    fflush( stdout );
    printf(ANSI_COLOR_RESET);

    if(comInit(portno) == 0)
        return 0;
    
    printf(ANSI_COLOR_YELLOW);
    printf("OK!");
    fflush( stdout );
    printf(ANSI_COLOR_RESET);
    
    while(1)
    {
        printf(ANSI_COLOR_YELLOW);
        printf("\n> Wait client ...");
        fflush( stdout );
        printf(ANSI_COLOR_RESET);
        
        startCom( &newsockfd );
        
        while(1)
        {
            printf(ANSI_COLOR_YELLOW);      
            printf("\n##################################################################");  
            printf( "\n> Ready to receive requests..." );
            fflush( stdout );
            printf(ANSI_COLOR_RESET);
        
            memset( TcpMessage, 0, sizeof( TcpMessage ) );
            getDataTcp( newsockfd, TcpMessage );
            
            if(TcpMessage[0] == 0)
            {
                printf(ANSI_COLOR_BOLD_RED);
                printf("\n> Loss of communication!!!");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
                break;
            }
            
            printf(ANSI_COLOR_YELLOW);        
            printf( "\n> New message received!" );
            fflush( stdout );
            printf(ANSI_COLOR_RESET);

            memset( payload, 0x00, sizeof( payload ) );
            if(1 == VerifAndDecryptMessage(TcpMessage, payload, &payloadSize))
            {
                char2send++;
                memset( payload, char2send, sizeof( payload ) );
                
                printf(ANSI_COLOR_YELLOW);        
                printf( "> Creating response message with <%02X>", char2send );
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
                
                signAndCiphMessage( payload, sizeof(payload), TcpMessage, 
                                    &TcpMessageSize, entityId);
                
                sendDataTcp(newsockfd, TcpMessage, sizeof(TcpMessage));
                
                printf(ANSI_COLOR_YELLOW);        
                printf( "> Sending OK!" );
                fflush( stdout );
            }
            else
            {
                /* Insecure comm. Actions may be taken */
                printf(ANSI_COLOR_BOLD_RED);        
                printf( "\n> Unsafe communication!");
                fflush( stdout );
                printf(ANSI_COLOR_RESET);
            }
        }

        close( newsockfd );
    }

    return( 0 );
}


/*****************************************************************************/
/*****************************************************************************/
/********************** S T A T I C   F U N C T I O N S **********************/
/*****************************************************************************/
/*****************************************************************************/
static int sendDataTcp( int sockfd, unsigned char buff[], int size ) 
{
  int n;
  if ( (n = write( sockfd, buff, size ) ) < 0 )
	printf("ERROR writing to socket");
	
    return n;
}


static int getDataTcp( int sockfd, unsigned char buff[] ) {

  int n;

  if ( (n = read(sockfd,buff,256) ) < 0 )
        printf("\n  . ERROR reading from socket");
        

  return n;
}


static int comInit(int portno)
{
    int retVal = 1;

    if ( ( sockfd = socket(AF_INET, SOCK_STREAM, 0) ) < 0 )
    {
        printf("ERROR opening socket");
        fflush( stdout );
        retVal = 0;
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons( portno );
    if (bind(sockfd, (struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
    {
        printf("ERROR on binding");
        fflush( stdout );
        retVal = 0;
    }
       
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    
    return retVal;
}

static int startCom(int *newsockfd)
{
    int retVal = 1;
    
    if ( ( *newsockfd = accept( sockfd, 
                                (struct sockaddr *) &cli_addr, 
                                (socklen_t*) &clilen) ) < 0 )
    {
        printf("ERROR on accept");
        fflush( stdout );
    }
    else
    {
        printf(ANSI_COLOR_YELLOW);        
        printf( "\n> Opened new communication with client");
        fflush( stdout );
        printf(ANSI_COLOR_RESET);
        retVal = 1;
    }

    return retVal;
}


static void getConexParameters( int *entityId, int *portId )
{
    char keyboard[100];
    char entity[2];
    char port[5];

    printf(  "  . Current entity: %d (can be 0-4)", *entityId);    
    printf("\n  . Current port:   %d (most be size 4)", *portId);
    printf("\n  . To change first type entity then port. Eg: <2-8081>. If not type <c>");
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
    }
}
/**********************************************************/
/**********************************************************/
/**********************************************************/




