/** \file Encoding_Chunked.cpp
 * Fast HTTP Auth Scanner -  Chunk encoding for handling transfer encoding.
 *
 * \author Andres Tarasco Acuna - http://www.tarasco.org (c) 2007 - 2008
*/
#include "Encoding_Chunked.h"
#include "../IoFunctions.h"
#include "../CallBack.h"
#include "../Build.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE
#endif

/******************************************************************************/
//! This function decodes the buffer returned by the remote HTTP Server when "Chunk encoding" is enabled.
/*!
	\param lpBuffer Buffer returned by the http server (Without headers )
	\param encodedlen length of lpBuffer
	\param decodedlen length of the returned decoded buffer
	\return Pointer to the decoded buffer.
	\note If the function fails due to malformed or incomplete datachunks, NULL is returned instead. If that happends, the user must use the original lpBuffer data
*/
/******************************************************************************/
static char *DecodeChunk(char *lpBuffer, unsigned int encodedlen, unsigned int *decodedlen)
{
    //char *decoded=NULL;
    //int decodedlen=0;
    char *encoded=lpBuffer;

    char chunkcode[MAX_CHUNK_LENGTH+1];
	char *p;
    unsigned long chunk=1;

	unsigned long lpBufferSize;
	PHTTPIOMapping HTTPIoMapping = NULL;

    *decodedlen=0;
    do {
        if (lpBuffer!=encoded){
			if (encodedlen<=2) {
				break;
			}
            encoded+=2;
            encodedlen-=2;
        }
        if (encodedlen>=MAX_CHUNK_LENGTH) {
			memcpy(chunkcode,encoded,MAX_CHUNK_LENGTH);
            chunkcode[MAX_CHUNK_LENGTH]='\0';
        } else {
			//memset(chunkcode,0,sizeof(chunkcode));
            memcpy(chunkcode,encoded,encodedlen);
            chunkcode[encodedlen]='\0';
        }
        p=strstr(chunkcode,"\r\n");
        if (!p)  //Do not decode block, due to chunk error
        {		 //Maybe we should append this data block
            //if (decoded) free(decoded);
			if (HTTPIoMapping)
			{
#ifdef __WIN32__RELEASE__
					CloseHandle(HTTPIoMapping->hTmpFilename);
					DeleteFileA(HTTPIoMapping->BufferedFileName);
#else
					close(HTTPIoMapping->hTmpFilename);
					rmdir(HTTPIoMapping->BufferedFileName);
#endif
					HTTPIoMapping->assigned=0;
			}
#ifdef _DBG_
            printf("DecodeChunk::error...\n");
#endif
            return(NULL);
        }
        *p='\0';
        chunk=strtol(chunkcode,NULL,16);
        if ( (unsigned int) encodedlen > strlen(chunkcode)+ 2 + chunk) {
/*
			if (!decoded) {
                decoded=(char*)malloc(chunk+1);
            }else
            {
                decoded=(char*)realloc(decoded,*decodedlen+chunk+1);
            }
            memcpy(decoded+*decodedlen,encoded+2+strlen(chunkcode),chunk);
*/
			if (!HTTPIoMapping){
					HTTPIoMapping = GetFileMapping(0,NULL);
					if (!HTTPIoMapping) return(NULL);
			}
			if (HTTPIoMapping) {
#ifdef __WIN32__RELEASE__
				WriteFile(HTTPIoMapping->hTmpFilename,encoded+2+strlen(chunkcode),chunk,&lpBufferSize,NULL);
#else
				//fwrite(encoded+2+strlen(chunkcode),chunk,1,HTTPIoMapping->hTmpFilename);
				write(HTTPIoMapping->hTmpFilename,encoded+2+strlen(chunkcode),chunk);
#endif
				HTTPIoMapping->MemoryLenght+=chunk;
			}
            *decodedlen+=chunk;
            encodedlen-=2+chunk+strlen(chunkcode);
            encoded+=2+chunk+strlen(chunkcode);
        } else {
			if (!HTTPIoMapping){
				HTTPIoMapping = GetFileMapping(0,NULL);
				if (!HTTPIoMapping) return(NULL);
			}
			if (HTTPIoMapping) {
#ifdef __WIN32__RELEASE__
				WriteFile(HTTPIoMapping->hTmpFilename,encoded+2+strlen(chunkcode),encodedlen-strlen(chunkcode)-2,&lpBufferSize,NULL);
#else
				//fwrite(encoded+2+strlen(chunkcode),encodedlen-strlen(chunkcode)-2,1,HTTPIoMapping->hTmpFilename);
				write(HTTPIoMapping->hTmpFilename,encoded+2+strlen(chunkcode),encodedlen-strlen(chunkcode)-2);
#endif
				HTTPIoMapping->MemoryLenght+=encodedlen-strlen(chunkcode)-2;
			}
/*
            if (!decoded) {
                decoded=(char*)malloc(chunk+1);
            }else
            {
                decoded=(char*)realloc(decoded,*decodedlen+chunk+1);
            }
            memcpy(decoded+*decodedlen,encoded+2+strlen(chunkcode),encodedlen-strlen(chunkcode)-2);
*/
            *decodedlen+=encodedlen-strlen(chunkcode)-2;
            encodedlen=0;
        }
//        decoded[*decodedlen]='\0';
    } while ( (encodedlen>0) && (chunk>0) );

	if (!HTTPIoMapping) return (NULL);
#ifdef __WIN32__RELEASE__
	WriteFile(HTTPIoMapping->hTmpFilename,"\x00",1,&lpBufferSize,NULL);
	HTTPIoMapping->hMapping = CreateFileMapping (HTTPIoMapping->hTmpFilename,
                           NULL,
                           PAGE_READWRITE,
                           0,
                           HTTPIoMapping->MemoryLenght+1,
                           NULL);
	HTTPIoMapping->BufferedPtr = (char*) MapViewOfFile (HTTPIoMapping->hMapping , FILE_MAP_ALL_ACCESS, 0,0,0);
#else
	write(HTTPIoMapping->hTmpFilename,"\x00",1);
	HTTPIoMapping->BufferedPtr = (char*) mmap (0, *decodedlen +1, PROT_READ | PROT_WRITE, MAP_SHARED, HTTPIoMapping->hTmpFilename, 0);
#endif
	//HTTPIoMapping->MemoryLenght = decodedlen;

	return(HTTPIoMapping->BufferedPtr);
    //return (decoded);
}
/******************************************************************************/
//! CallBack Function. This function is called from the DoCallBack() function once its registered and will intercept the callback information.
/*!
	\param cbType CallBack Source Type. Valid options are CBTYPE_CLIENT_REQUEST , CBTYPE_CLIENT_RESPONSE , CBTYPE_BROWSER_REQUEST , CBTYPE_SERVER_RESPONSE
	\param HTTPHandle HTTP Connection Handle with information about remote target (like ip address, port, ssl, protocol version,...)
	\param prequest struct containing all information related to the HTTP Request.
	\param presponse struct containing information about http reponse. This parameter could be NULL if the callback type is CBTYPE_CLIENT_REQUEST or CBTYPE_CLIENT_RESPONSE because request was not send yet.
	\return the return value CBRET_STATUS_NEXT_CB_CONTINUE indicates that the request (modified or not) its ok. If a registered handler blocks the request then CBRET_STATUS_CANCEL_REQUEST is returned. This value indicates that the response is locked
    \note This function does not block requests, only tries to decode HTTP response.
*/
/******************************************************************************/
int CBDecodeChunk(int cbType,HTTPHANDLE HTTPHandle,PHTTP_DATA  *prequest,PHTTP_DATA *presponse)
{
	//PHTTP_DATA request = *prequest;
	PHTTP_DATA response = *presponse;
    if ((cbType == CBTYPE_CLIENT_RESPONSE) || (cbType == CBTYPE_PROXY_RESPONSE) )
	{
	 if (response) {
		char *p=GetHeaderValue(response->Header,"Transfer-Encoding:",0);
		if (p)
		{
			if (strnicmp(p,"chunked",7)==0) {
				unsigned int decodedlen;
				char *decoded= DecodeChunk(response->Data,response->DataSize,&decodedlen);
				if (decoded)
				{
					char tmp[256];
					response->Data = DeleteFileMapping(response->Data);
					if (response->Data)
					{
						//printf("[Encoding_Chunked CB: Unable to delete mapping against response->Data. Memory leak here\n");
						free(response->Data);
					}
					response->Data=decoded;
					response->DataSize=decodedlen;
					RemoveHeader(response,"Transfer-Encoding: ");
					sprintf(tmp,"Content-Length: %i\r\n",decodedlen);
					AddHeader(response, tmp);
				}
			}
			free(p);
		}
	 }
	}

	return(CBRET_STATUS_NEXT_CB_CONTINUE);

}
#if 0
/******************************************************************************/
 //! This function analyzes chunk encocoded data and returns the number of pending bytes (unreaded yet)
/*!
	\param lpBuffer data returned by the http server
	\param encodedlen length of the chunked data
	\return Number of bytes to read.
	\note  ERROR_MORE_DATA_NEEDED is returned if the chunk is not complete.

*/
/******************************************************************************/
int ParseDataChunks(char *lpBuffer, unsigned int encodedlen)
{
    /*
    Non Recursive version
    Return the number of bytes to needed to finish the chunk
    */

    char *encoded=lpBuffer;
    char chunkcode[MAX_CHUNK_LENGTH+1];
    char *p;
    unsigned long chunk=1;
    //	printf("EL buffer es:\n!%s!\n",lpBuffer);

    do {
        if (lpBuffer!=encoded)
        {
            encoded+=2;
            encodedlen-=2;
        }
        if (encodedlen>=MAX_CHUNK_LENGTH) {
            memcpy(chunkcode,encoded,MAX_CHUNK_LENGTH);
            chunkcode[MAX_CHUNK_LENGTH]='\0';
            p=strstr(chunkcode,"\r\n");
            if (!p) {
				return(0); } //Error parseando protocolo
            *p='\0';
        } else {
            if (encodedlen<=0) {
                break;
            }
            memcpy(chunkcode,encoded,encodedlen);
            chunkcode[encodedlen]='\0';
            p=strstr(chunkcode,"\r\n");
            if (p==NULL) break; //return (ERROR_MORE_DATA_NEEDED);
            *p='\0';
        }
        chunk=strtol(chunkcode,NULL,16);
        if (chunk==0) return (0);
        if ( (unsigned int) encodedlen > 2 + strlen(chunkcode)+chunk) {
            encodedlen-=2+chunk+strlen(chunkcode);
            encoded+=2+chunk+strlen(chunkcode);
        } else break;
    } while (1);
	return (ERROR_MORE_DATA_NEEDED);

}
/******************************************************************************/

#endif
