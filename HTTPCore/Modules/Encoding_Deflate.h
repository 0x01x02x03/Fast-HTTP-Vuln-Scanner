#ifdef _ZLIB_SUPPORT_
#ifndef _ENCODING_DEFLATE_
#define _ENCODING_DEFLATE_

#include "../HTTP.h"

#define NORMAL_DATA	 0
#define GZIP_DATA 	 1
#define DEFLATE_DATA 2

int CBDeflate(int cbType,HTTPHANDLE HTTPHandle,PHTTP_DATA *prequest,PHTTP_DATA *presponse);

#endif
#endif


