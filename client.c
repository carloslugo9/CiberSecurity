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
static int func( int a );
static void sendData( int sockfd, int x );
static int getData( int sockfd );
static void error(char *msg);

/*****************************************************************************/
/*****************************************************************************/
/********************** P U B L I C   F U N C T I O N S **********************/
/*****************************************************************************/
/*****************************************************************************/
int main( int argc, char *argv[] )
{
    unsigned char TcpMessage[200];
    int TcpMessageSize;
    
    printf(ANSI_COLOR_BOLD_GREEN);
    printf("**************************************************************\n");
    printf("*************************** SERVER ***************************\n");
    printf("**************************************************************\n\n");
    
    printf(ANSI_COLOR_YELLOW);
    printf("> Getting my keys ... \n");
    printf(ANSI_COLOR_RESET);
    getMyKeys();

    printf(ANSI_COLOR_YELLOW);
    printf("\n> Getting public keys ...");
    printf(ANSI_COLOR_RESET);
    geyKeyDatabase();

    printf(ANSI_COLOR_YELLOW);
    printf("\n> Ready to send and receive messages ...");
    printf(ANSI_COLOR_RESET);




    unsigned char payload[32];
    int payloadSize;
    memset( payload, 	1, sizeof( payload ) );
    memset( TcpMessage, 0, sizeof( TcpMessage ) );
    
    dump_buf( "\nMyBuffer:\n", TcpMessage, sizeof( TcpMessage ) );
    dump_buf( "Payload:  ", payload, sizeof( payload ) );
    
    signAndCiphMessage(payload, sizeof(payload), TcpMessage, &TcpMessageSize);
    
    //dump_buf( "\nMyBuffer:\n", TcpMessage, sizeof( TcpMessage ) );
    
    /* Recibir */
    printf(ANSI_COLOR_YELLOW);
    printf("\n> Rx");
    printf(ANSI_COLOR_RESET);
    
    memset( payload, 	0, sizeof( payload ) );
    dump_buf( "Payload:  ", payload, sizeof( payload ) );
    VerifAndDecryptMessage(TcpMessage, TcpMessageSize, payload, &payloadSize);
    dump_buf( "Payload:  ", payload, sizeof( payload ) );


   
    int sockfd, n;
    int portno = 8081;
    char serverIp[] = "192.168.43.64"; /*<-- Cambiar!! */
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char buffer[256];
    int data;

    if (argc < 3) {
      printf( "contacting %s on port %d\n", serverIp, portno );
      // exit(0);
    }
    if ( ( sockfd = socket(AF_INET, SOCK_STREAM, 0) ) < 0 )
        printf("ERROR opening socket");

    if ( ( server = gethostbyname( serverIp ) ) == NULL ) 
        printf("ERROR, no such host\n");
    
    bzero( (char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy( (char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(portno);
    if ( connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) 
        printf("ERROR connecting");

    for ( n = 0; n < 10; n++ ) {
      sendData( sockfd, n );
      data = getData( sockfd );
      printf("%d ->  %d\n",n, data );
    }
    sendData( sockfd, -2 );

    close( sockfd );



    return( 0 );
}


/*****************************************************************************/
/*****************************************************************************/
/********************** S T A T I C   F U N C T I O N S **********************/
/*****************************************************************************/
/*****************************************************************************/

/* The server waits for a connection request from a client.
The server assumes the client will send positive integers, which it sends back multiplied by 2.
If the server receives -1 it closes the socket with the client.
If the server receives -2, it exits.
 */
static int func( int a ) {
   return 2 * a;
}

static void sendData( int sockfd, int x ) {
  int n;

  char buffer[32];
  sprintf( buffer, "%d\n", x );
  if ( (n = write( sockfd, buffer, strlen(buffer) ) ) < 0 )
	printf("ERROR writing to socket");
  buffer[n] = '\0';
}

static int getData( int sockfd ) {
  char buffer[32];
  int n;

  if ( (n = read(sockfd,buffer,31) ) < 0 )
        printf("ERROR reading from socket");
  buffer[n] = '\0';
  return atoi( buffer );
}

static void error(char *msg) {
    perror(msg);
    exit(0);
}




