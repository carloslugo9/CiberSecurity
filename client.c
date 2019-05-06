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
    char          keyboard[100];
    int           sockfd, portno = 8081;
    char          serverIp[20] = "192.168.43.166";
    
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
    printf("> Initializing communications ... \n");
    printf(ANSI_COLOR_RESET);
    
    if(comInit(&sockfd , portno, serverIp) == 0)
        return 0;

    while(1)
    {
        memset( keyboard, 0, sizeof( keyboard ) );
        scanf("%s",keyboard);
        

        
        memset( payload,    1, sizeof( payload ) );
        memset( TcpMessage, 0, sizeof( TcpMessage ) );
        
        signAndCiphMessage(payload, sizeof(payload), TcpMessage, 
			   			   &TcpMessageSize, entityId);
        
        printf("\nSending...");
        sendDataTcp(sockfd, TcpMessage, sizeof(TcpMessage));        
        
    }

	close( sockfd );


    VerifAndDecryptMessage(TcpMessage, payload, &payloadSize);





    //sendDataTcp(sockfd, TcpMessage, sizeof(TcpMessage));
    
    //sendDataTcp(sockfd, TcpMessage, sizeof(TcpMessage));
    
    //getDataTcp( sockfd, TcpMessage );
    


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
        printf("ERROR opening socket");

    if ( ( server = gethostbyname( serverIp ) ) == NULL ) 
        printf("ERROR, no such host\n");

    bzero( (char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    
    bcopy( (char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(portno);
    
    if ( connect(*sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) 
    {
        printf("ERROR connecting");
    }
    else
    {
        printf( "  . Opened new communication with client" );
        retVal = 1;
    }
        
    return retVal;
}


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
        printf("ERROR reading from socket");
        

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
        
    }//3-8081-192.168.43.166>
}


