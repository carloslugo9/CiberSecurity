#Compiler
CC       = gcc -g
CFLAGS   = -Wall
#Libraries to use
LDFLAGS  = -Lmbedtls/library -lmbedtls -lmbedx509 -lmbedcrypto
# Includes
INC      = -Imbedtls/include/mbetls -Imbedtls/include -Iprotocol_mngr
#objects part of the final program
OBJFILES = 
#Targets
TARGET_CLNT = clientProgram
TARGET_SERV = serverProgram
TARGET_GEN  = keyGenerator/keyGenerator
#Input source
CLIENT_SRC    = client.c 
SERVER_SRC    = server.c
PROTOCOL_MNGR = protocol_mngr/protocol_mngr.c
K_GEN_SRC     = keyGenerator/keyGenerator.c

.SILENT:

TARGETS: ${SERVER_SRC} ${CLIENT_SRC} ${PROTOCOL_MNGR}
	$(CC) $(CFLAGS) $(INC) ${SERVER_SRC} ${PROTOCOL_MNGR} $(LDFLAGS) -o ${TARGET_SERV}
	$(CC) $(CFLAGS) $(INC) ${CLIENT_SRC} ${PROTOCOL_MNGR} $(LDFLAGS) -o ${TARGET_CLNT}


keys:
	${CC} $(CFLAGS) $(INC) ${K_GEN_SRC}  $(LDFLAGS) -o ${TARGET_GEN}

clean:
	rm -f $(OBJFILES) $(TARGET_CLNT) ${TARGET_SERV} ${TARGET_GEN} *~
