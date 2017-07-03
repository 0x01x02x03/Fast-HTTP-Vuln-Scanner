#ifndef _ENCODING_CHUNKED_
#define _ENCODING_CHUNKED_

#include "../HTTP.h"

#define MAX_CHUNK_LENGTH						10
#define ERROR_MORE_DATA_NEEDED 					-1
#define ERROR_PARSING_DATA     					0xFFFFFF

int CBDecodeChunk(int cbType,HTTPHANDLE HTTPHandle,PHTTP_DATA *request,PHTTP_DATA *response);
//int ParseDataChunks(char *lpBuffer, unsigned int encodedlen);

#endif

