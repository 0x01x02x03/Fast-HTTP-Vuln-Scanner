#ifndef _IO_FUNCTIONS_
#define _IO_FUNCTIONS_

#include "HTTPCore.h"

#define MAX_CHECK_TIME_FOR_BW_UTILIZATION  200
#define CONN_TIMEOUT 10
#define READ_TIMEOUT 10


PHTTP_DATA		 ReadHTTPResponseData(STABLISHED_CONNECTION *conexion, PHTTP_DATA request, void *mutex);
int				 SendHTTPRequestData (STABLISHED_CONNECTION *conexion, PHTTP_DATA request );
int				 StablishConnection  (STABLISHED_CONNECTION *connection );

int				InitFileMapping(void);
int				EndFileMapping(void);
char			*DeleteFileMapping(void* ptr);
PHTTPIOMapping	GetFileMapping(unsigned int DataSize, char *lpData );

#endif
