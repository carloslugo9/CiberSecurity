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



/*****************************************************************************/
/*****************************************************************************/
/********************* S T A T I C   P R O T O T Y P E S *********************/
/*****************************************************************************/
/*****************************************************************************/



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

#if 0
     int sockfd, newsockfd, portno = 8081, clilen;
     char buffer[256];
     struct sockaddr_in serv_addr, cli_addr;
     int n;
     int data;

     printf( "using port #%d\n", portno );
    
     sockfd = socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) 
         //error( const_cast<char *>("ERROR opening socket") );
	 printf("ERROR opening socket");
     bzero((char *) &serv_addr, sizeof(serv_addr));

     serv_addr.sin_family = AF_INET;
     serv_addr.sin_addr.s_addr = INADDR_ANY;
     serv_addr.sin_port = htons( portno );
     if (bind(sockfd, (struct sockaddr *) &serv_addr,
              sizeof(serv_addr)) < 0) 
       //error( const_cast<char *>( "ERROR on binding" ) );
	printf("ERROR on binding");
     listen(sockfd,5);
     clilen = sizeof(cli_addr);
  
     //--- infinite wait on a connection ---
     while ( 1 ) {
        printf( "waiting for new client...\n" );
        if ( ( newsockfd = accept( sockfd, (struct sockaddr *) &cli_addr, (socklen_t*) &clilen) ) < 0 )
            //error( const_cast<char *>("ERROR on accept") );
		printf("ERROR on accept");
        printf( "opened new communication with client\n" );
        while ( 1 ) {
	     //---- wait for a number from client ---
             data = getData( newsockfd );
             printf( "got %d\n", data );
             if ( data < 0 ) 
                break;
                
             data = func( data );

             //--- send new data back --- 
	     printf( "sending back %d\n", data );
             sendData( newsockfd, data );
	}
        close( newsockfd );

        //--- if -2 sent by client, we can quit ---
        if ( data == -2 )
          break;
     }


#endif


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
int func( int a ) {
   return 2 * a;
}

void sendData( int sockfd, int x ) {
  int n;

  char buffer[32];
  sprintf( buffer, "%d\n", x );
  if ( (n = write( sockfd, buffer, strlen(buffer) ) ) < 0 )
//    error( const_cast<char *>( "ERROR writing to socket") );
	printf("ERROR writing to socket");
  buffer[n] = '\0';
}

int getData( int sockfd ) {
  char buffer[32];
  int n;

  if ( (n = read(sockfd,buffer,31) ) < 0 )
    //error( const_cast<char *>( "ERROR reading from socket") );
        printf("ERROR reading from socket");
  buffer[n] = '\0';
  return atoi( buffer );
}
/**********************************************************/
/**********************************************************/
/**********************************************************/




    return( 0 );
}


