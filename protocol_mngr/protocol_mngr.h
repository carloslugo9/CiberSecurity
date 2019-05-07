#ifndef PROTOCOL_MANGR_H_
#define PROTOCOL_MANGR_H_

/*****************************************************************************/
/*****************************************************************************/
/**************** I N C L U D E S   &   D E F I N I T I O N S ****************/
/*****************************************************************************/
/*****************************************************************************/
#include <stdio.h>

/*****************************************************************************/
/*****************************************************************************/
/********************** P U B L I C   F U N C T I O N S **********************/
/*****************************************************************************/
/*****************************************************************************/

void signAndCiphMessage( unsigned char payload[], 
	                              int  payloadSize,
			             unsigned char tcpMessage[],
  			                      int  *tcpMsgSize,
  			                      int  entity );

int VerifAndDecryptMessage(unsigned char tcpMessage[],
							unsigned char payload[],
									 int  *payloadSize);

void FromFileToMemory(char *src, char *dst, int len);

void dump_buf( const char *title, unsigned char *buf, size_t len );

#endif /*PROTOCOL_MANGR_H_*/
