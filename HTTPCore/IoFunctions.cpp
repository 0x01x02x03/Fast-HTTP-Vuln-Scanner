#include "IoFunctions.h"
#include "Threading.h"
#include "Modules/Encoding_Chunked.h"

HTTPIOMapping	HTTPIoMappingData[MAXIMUM_OPENED_HANDLES];

CRITICAL_SECTION IoMappingLock;
#ifdef __WIN32__RELEASE__
#ifndef __uint64
#define __uint64 unsigned __int64
#endif
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif

struct timezone
{
	int  tz_minuteswest; /* minutes W of Greenwich */
	int  tz_dsttime;     /* type of dst correction */
};

static int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	FILETIME ft;
	unsigned __int64 tmpres = 0;
	static int tzflag;

	if (NULL != tv)
	{
		GetSystemTimeAsFileTime(&ft);

		tmpres |= ft.dwHighDateTime;
		tmpres <<= 32;
		tmpres |= ft.dwLowDateTime;

		/*converting file time to unix epoch*/
		tmpres /= 10;  /*convert into microseconds*/
		tmpres -= DELTA_EPOCH_IN_MICROSECS;
		tv->tv_sec = (long)(tmpres / 1000000UL);
		tv->tv_usec = (long)(tmpres % 1000000UL);
	}

	if (NULL != tz)
	{
		if (!tzflag)
		{
			_tzset();
			tzflag++;
		}
		tz->tz_minuteswest = _timezone / 60;
		tz->tz_dsttime = _daylight;
	}

	return 0;
}
#endif

/*******************************************************************************************/
//! This function checks if the  transfered data exceeds the current bandwidth limit.
/*!
\param ChunkSize Size of the transfered data block.
\param LastTime timeval struct that stores the moment when the application began to receive data.
\param CurrentTime timeval struct that stores the actual time
\param MAX_BW_LIMIT Bandwitdh limit (kbps)
\return Number of miliseconds that the thread should wait until new data is readed from the remote server.
-1 is returned if there is no enough information to calculate bandwidth.

*/
/***************************************************************/
static int LimitIOBandwidth(unsigned long ChunkSize, struct timeval LastTime, struct timeval CurrentTime, int MAX_BW_LIMIT)
{

	if ( ( LastTime.tv_usec || LastTime.tv_sec ) && MAX_BW_LIMIT )
	{
		 __uint64  TotalTime = ((CurrentTime.tv_usec + CurrentTime.tv_sec*1000000) - (LastTime.tv_usec + LastTime.tv_sec*1000000) ) / 1000;
		if (TotalTime >= MAX_CHECK_TIME_FOR_BW_UTILIZATION ) //check Bw each 200ms
		{
			__uint64  CurrentBW = (ChunkSize *1000 ) / (TotalTime *1024 )  ; //Obtener kbps
			//printf("Hemos tardado %I64d ms para %i bytes - Bandwidth: %I64d kbps (%i KB/s)\n",TotalTime, ChunkSize,CurrentBW,CurrentBW/8);
			if (CurrentBW > MAX_BW_LIMIT  )
			{
				__uint64 WaitFor = (ChunkSize *1000 ) / (MAX_BW_LIMIT *1024) ;
				//printf("Esperar %i ms\n",WaitFor);
				return((int)WaitFor);
			}
		} else {
			return(-1);
		}
	}
	return(0);
}



/*******************************************************************************************/
//! This function sends an HTTP request to the remote webserver. a CONEXION struct with initialized sockets. If the connection was previously initialized that struct will be resused.
/*!
\param conexion struct returned by GetSocketConnection that includes the information of the remote host and valid socket.
\param request HTTP request verbs and data to be delivered to the remote HTTP Server
\return If there is no error, 1 is returned.
\note This Function only sends data, handling the responses from the HTTP server is done outside.
*/
/***************************************************************/
int SendHTTPRequestData(STABLISHED_CONNECTION *conexion, PHTTP_DATA request) {

	if ((conexion) && (request)) {
		if (conexion->NeedSSL) {
#ifdef _OPENSSL_SUPPORT_
			int err=SSL_write(conexion->ssl, request->Header, request->HeaderSize);
			if (err>0) {
				if (request->DataSize)
				{
					err=SSL_write(conexion->ssl, request->Data, request->DataSize);
				}
			}
			if (err <=0) {
#ifdef _DBG_
				printf("SSL_write ERROR1: %s:%i\n",conexion->targetDNS,conexion->port);
#endif
				return(0);
			}
#else
			return (0);
#endif
		} else {
			int err = send(conexion->datasock, request->Header, request->HeaderSize, 0);
			if (err > 0) {
				if (request->DataSize) {
					err = send(conexion->datasock, request->Data, request->DataSize, 0);
				}
			}
			if (err <= 0) {
#ifdef _DBG_
				printf("Send() ERROR1: %s:%i\n",conexion->targetDNS,conexion->port);
#endif
				return (0);
			}
		}
	}
	return (1);
}

/*******************************************************************************************/
//! This function reads an HTTP response stream from the remote webserver.
/*!
\param conexion struct returned by GetSocketConnection that includes the information of the remote host and valid socket.
\param request HTTP request that was sent before. This param is needed to resend the request
\param lock mutext used for exclusive access.
\return pointer to a HTTP_DATA Struct with the HTTP Response or NULL if the remote host can not be reached.
*/
/*******************************************************************************************/
PHTTP_DATA ReadHTTPResponseData(STABLISHED_CONNECTION *conexion, PHTTP_DATA request, void *lock)
{
	/* IO VARIABLES TO HANDLE HTTP RESPONSE */
	struct timeval tv;		       /* Timeout for select events */
	fd_set fdread, fds, fderr;     /* descriptors to be signaled by select events */
	char buf[BUFFSIZE+1];          /* Temporary buffer where the received data is stored */
	int read_size;			       /* Size of the received data chunk */
	char *lpBuffer = NULL;	       /* Pointer that stores the returned HTTP Data until its flushed to disk or splited into headers and data */
	unsigned int BufferSize = 0;   /* Size of the returned HTTP Data lpBuffer */
	char *HeadersEnd = NULL;       /* Pointer to the received buffer that indicates where the HTTP headers  end and HTTP data begins */
	int offset = 0;                /* Number of bytes from the end of headers to the start of HTTP data. Usually 4bytes for "\r\n\r\n" if its RFC compliant*/
	int BytesToBeReaded = -1;      /* Number of bytes remaining to be readed on the HTTP Stream (-1 means that the number of bytes is still unknown, 0 that we have reached the end of the html data ) */
	int i;                         /* Just a counter */
	int pending      =  0;         /* Signals if there is Buffered data to read under and SSL connection*/
	PHTTP_DATA response = NULL;    /* Returned HTTP Information */


    /* SOME CRITICAL INFORMATION THAT WE WILL GATHER FROM THE HTTP STREAM*/
	unsigned int ChunkEncodeSupported = 0; /* HTTP PROTOCOL FLAG: Server supports chunk encoding */
	unsigned int ConnectionClose	  = 0; /* HTTP PROTOCOL FLAG: Connection close is needed because of server header or protocol I/O error */
	unsigned int ContentLength		  = 0; /* HTTP PROTOCOL FLAG: Server support the ContentLength header */

	/* IO BW LIMIT CONTROL VARIABLES */
	int BwDelay;                   /* Number of miliseconds that the application should wait until reading the next data chunk */
	struct timeval LastTime={0,0}; /* Stores the time when the first data chunk is readed */
	struct timeval CurrentTime;    /* Stores the time when the last data chunk is readed to check for the current bw */
	unsigned int ChunkSize = 0;    /* Stores how many bytes have been readed   */

	/* CHUNK ENCODING VARIABLES  */
	int ChunkNumber  =  0;         /* If Chunkencoding is supported, this variable stores the number of fully received chunks */
	char *encodedData = NULL;      /* Pointer to a buffer that stores temporary data chunks to verify how many bytes are still needed to be readed */
	unsigned int encodedlen = 0 ;  /* Lenght of the encodedData Buffer */
	char *TmpChunkData = NULL;     /* Pointer to a buffer that stores temporary data chunks to verify how many bytes are still needed to be readed */

	/* I/O FILE MAPPING FOR THE HTTP DATA */
	PHTTPIOMapping HTTPIOMappingData = NULL;
#ifdef __WIN32__RELEASE__
	DWORD lpBufferSize;			   /* Number of bytes written to the temporary file */
#endif


	LockMutex(&conexion->lock);
	tv.tv_sec = READ_TIMEOUT;
	tv.tv_usec = 0;

	while (BytesToBeReaded != 0)
	{

		/* Wait for readable data at the socket */
		FD_ZERO(&fds);
		FD_SET(conexion->datasock, &fds);
		FD_ZERO(&fderr);
		FD_SET(conexion->datasock, &fderr);
		FD_ZERO(&fdread);
		FD_SET(conexion->datasock, &fdread);
		

		if (!pending)
		{

			i = select((int) conexion->datasock + 1, &fdread, NULL,&fderr, &tv);

#ifdef __WIN32__RELEASE__
			GetSystemTimeAsFileTime (&conexion->tlastused);
#else
			time(&conexion->tlastused);
#endif
			/* No events from select means that connection timeout (due to network error, read timeout or maybe http protocol error */
			if ((i == 0))
			{
				//Como liberamos lpBuffer con el mapping, debemos verificar que exista "hTmpFilename" o lo que es lo mismo, la struct "response"
				if ( (!lpBuffer) && (!HTTPIOMappingData) ) {
					UnLockMutex(&conexion->lock);
					LockMutex(lock);
#ifdef _DBG_
					printf("TIMEOUT LEYENDO...\n");
#endif
					FreeConnection(conexion);
					UnLockMutex(lock);
					if (conexion->ConnectionAgainstProxy) { 
						return ( NULL) ;
					} else {
						return (InitHTTPData(NULL,NULL));
					}
					//return(NULL);
				}
				ConnectionClose = 1;
				break;
			}
			read_size = 1;
		}

		/* Verifify that there is pending readable data (over ssl) */
		if ((FD_ISSET(conexion->datasock, &fdread)) || pending)
		{
			if (conexion->NeedSSL) {
#ifdef _OPENSSL_SUPPORT_
				read_size=SSL_read(conexion->ssl, buf, BytesToBeReaded> sizeof(buf)-1 ? sizeof(buf)-1 :BytesToBeReaded);
				//if (read_size>0) buf[read_size]='\0'; else buf[0]='\0';
				pending= SSL_pending(conexion->ssl);
				int ret=SSL_get_error(conexion->ssl,read_size);
				//printf(" RET: %i (%i bytes) - pending: %i\n",ret,read_size,SSL_pending(conexion->ssl));
#ifdef _DBG_
				printf("SSL: read: %i bytes\n",read_size);
#endif
#endif
			} else {
				read_size = recv(conexion->datasock, buf, BytesToBeReaded > sizeof(buf) - 1 ? sizeof(buf) - 1 : BytesToBeReaded, 0);
			}
			if (read_size>0) buf[read_size]='\0'; else buf[0]='\0';
#ifdef _DBG_
			if (read_size>0)
			{
			printf("---------- read: \n%s\n-----------\n",buf); fflush(stdout);
			}
#endif
		}

		/* Verify if there are errors */
		if ((!pending) && ((FD_ISSET(conexion->datasock, &fderr)) || (read_size <= 0)))
		{
//			printf("llegamos aqui con read_size = %i\n",read_size);
			if (read_size <= 0)
			{
				if ( (!lpBuffer) && (HTTPIOMappingData == NULL) )
				{
					// If the socket is reused for more than one request, always try to send it again.
					UnLockMutex(&conexion->lock);
					if (conexion->NumberOfRequests > 0) {
//						printf("peticiones >0\n");
#ifdef _DBG_
						printf("CONECTA::DBG Error recv() en peticion reutilizada\n");
						printf("LLAMANDO A StablishConnection desde peticion fallida reutilizada\n");
#endif
						LockMutex(lock);
						shutdown(conexion->datasock,2);
						closesocket(conexion->datasock);
						i = StablishConnection(conexion);
						if (!i) {
							FreeConnection(conexion);
							UnLockMutex(lock);
							return (NULL);
						}
						for (i = 0; i <= conexion->PENDING_PIPELINE_REQUESTS - 1; i++) {
							SendHTTPRequestData(conexion,conexion->PIPELINE_Request[i]);
						}

						UnLockMutex(lock);
						return ReadHTTPResponseData(conexion, request, lock);
					} else {
//						printf("peticiones <=0\n");
#ifdef _DBG_
						printf("CONECTA::DBG Error recv(). Se han recibido 0 bytes. Purgando conexion..\n");
#endif
						LockMutex(lock);
						//RemovePipeLineRequest(conexion);
						FreeConnection(conexion);
						UnLockMutex(lock);
						return (InitHTTPData(NULL,NULL));
					}
				}
				
			}
#ifdef _DBG_
			if (FD_ISSET(conexion->datasock, &fderr)) printf("es fderr\n");
#endif
			ConnectionClose = 1;
			BytesToBeReaded = 0;
			//printf("cerramos conexion\n"); exit(1);
			//break;
		}
		/* END OF I/O READ FUNCTIONS. NOW WE ARE GOING TO PARSE THE DATA */


		/* WRITE RECEIVED DATA (IF POSSIBLE) TO A TEMPORARY FILE  */

		if (read_size>0) 
		{
			if (HTTPIOMappingData) 
			{
	#ifdef __WIN32__RELEASE__
				WriteFile(HTTPIOMappingData->hTmpFilename,(unsigned char*)buf,read_size,&lpBufferSize,NULL);
				BufferSize += read_size;
	#else
				write(HTTPIOMappingData->hTmpFilename,buf,read_size);
				BufferSize += read_size;
	#endif

			} else {
				lpBuffer = (char*) realloc(lpBuffer, BufferSize + read_size + 1);
				memcpy(lpBuffer + BufferSize, buf, read_size);
				BufferSize += read_size;
				lpBuffer[BufferSize] = '\0';
			}
		}


		/* I/O DELAY OPTIONS - CHECK IF WE NEED TO WAIT TO AVOID NETWORK CONGESTION */
		if ( (conexion->BwLimit) && (read_size>0) )
		{
			ChunkSize +=read_size;
			gettimeofday(&CurrentTime,NULL);
			BwDelay = LimitIOBandwidth( ChunkSize, LastTime, CurrentTime,conexion->BwLimit);
			if (BwDelay >= 0){
				Sleep(BwDelay);
				gettimeofday(&LastTime,NULL);
				ChunkSize=0;
			}
		}

		//#define _DBG_
		if ( (!HeadersEnd) && (read_size >0) )//Buscamos el fin de las cabeceras
		{
			char *p = strstr(lpBuffer, "\r\n\r\n");
			if (p) {
				offset = 4;
				HeadersEnd = p;
			}
			p = strstr(lpBuffer, "\n\n"); // no rfc compliant (like d-link routers)
			if (p)
				if ((!HeadersEnd) || (p < HeadersEnd)) {
					offset = 2;
					HeadersEnd = p;
				}
				if (HeadersEnd) {

					if (strnicmp(lpBuffer, "HTTP/1.1 100 Continue", 21) == 0) { //HTTP 1.1 Continue Message.
						free(lpBuffer);
						return (ReadHTTPResponseData(conexion, request, lock));
					}
					response = InitHTTPData(NULL,NULL);
					response->HeaderSize = (unsigned int)(HeadersEnd - lpBuffer) + offset; //We must include offset (\r\n\r\n) into Header Size to avoid errors reading chunks
#ifdef _DBG_
					printf("HeaderSize vale %i de %ibytes\n",response->HeaderSize,BufferSize);
#endif
					response->Header = (char*) realloc(response->Header, response->HeaderSize + 1);// offset + 1);
					memcpy(response->Header, lpBuffer, response->HeaderSize);// + offset );
					response->Header[response->HeaderSize] = '\0';
#ifdef _DBG_
					printf("Value: %s\n",response->Header);
#endif
					

					if (response->HeaderSize>8){ 
						if (strcmp(response->Header+9,"204")==0){
							return(response);
						}
						//Use "Connection: Close" as default for HTTP/1.0
						if (response->Header[7] =='0') ConnectionClose = 1;

					}

					p = GetHeaderValue(response->Header, "Connection:", 0);
					if (p) {
						if (strnicmp(p, "close", 7) == 0) {
							ConnectionClose = 1;
						} else if (strnicmp(p, "Keep-Alive", 10) == 0) {
							ConnectionClose = 0;
						}
						free(p);
					} else {
							p = GetHeaderValue(response->Header, "Proxy-Connection:", 0);
							if (p) 
							{
								if (strnicmp(p, "close", 7) == 0) 
								{
									ConnectionClose = 1;
								} else if (strnicmp(p, "Keep-Alive", 10) == 0) {
									ConnectionClose = 0;
								}
								free(p);					
							}							
					}					

					if ((p = GetHeaderValue(response->Header, "Content-Length:", 0))
						!= NULL) {
							ContentLength = atoi(p);
							if (p[0] == '-') //Negative Content Length
							{
								ConnectionClose = 1;
								free(lpBuffer);
								lpBuffer = NULL;
								break;
								/*					} else if ((MAX_DOWNLOAD_DATA) && (ContentLength
								> MAX_DOWNLOAD_DATA)) {
								ContentLength = MAX_DOWNLOAD_DATA;
								*/
							} else {
								BytesToBeReaded = ContentLength - BufferSize
									+ response->HeaderSize;// - offset;
							}
							free(p);
					}
					if (strnicmp(request->Header, "HEAD ", 5) == 0) { //HTTP 1.1 HEAD RESPONSE DOES NOT SEND BODY DATA.
						if ((lpBuffer[7] == '1') && (ContentLength)) {
							free(lpBuffer);
							lpBuffer = NULL;
							break;
						}
					}

					p = GetHeaderValue(response->Header, "Transfer-Encoding:", 0);
					if (p) {
						if (strnicmp(p, "chunked", 7) == 0) {
							ChunkEncodeSupported = 1;
#ifdef _DBG_
							printf("Leido content chunked\n");
#endif
						}
						free(p);
					}
					BufferSize = BufferSize - response->HeaderSize;

					//Check Status code.
					//HTTP/1.1 204


					HTTPIOMappingData = GetFileMapping(0,NULL);
					if (HTTPIOMappingData)
					{
#ifdef __WIN32__RELEASE__
						WriteFile(HTTPIOMappingData->hTmpFilename,(unsigned char*)lpBuffer + response->HeaderSize,BufferSize,&lpBufferSize,NULL);
#else
						//fwrite(lpBuffer + response->HeaderSize,BufferSize,1,HTTPIOMappingData->hTmpFilename);
						write(HTTPIOMappingData->hTmpFilename,lpBuffer + response->HeaderSize,BufferSize);
#endif

						TmpChunkData = (char*)malloc(BufferSize + BUFFSIZE +1);
						memcpy(TmpChunkData,lpBuffer + response->HeaderSize,BufferSize);
						encodedlen=BufferSize;
						TmpChunkData[BufferSize]='\0';
						free(lpBuffer);
						lpBuffer=NULL;
					}
					/*
					#else

					memcpy(lpBuffer, lpBuffer + response->HeaderSize, BufferSize);
					lpBuffer[BufferSize] = '\0';
					lpBuffer = (char*) realloc(lpBuffer, BufferSize + 1);
					#endif
					*/
				}

		}


		/* We Must Validate  here the chunked Data */
		if ( (ChunkEncodeSupported) && (read_size>0 ) )
		{
			char chunkcode[MAX_CHUNK_LENGTH+1];
			char *p;
			unsigned long chunk=1;

			encodedData = TmpChunkData;
			if (ChunkNumber>0) {
				/* Si no es asi, los datos ya los hemos copiado de lpBuffer + response->HeaderSize */
				memcpy(TmpChunkData+encodedlen,buf,read_size);
				encodedlen+=read_size;
				TmpChunkData[encodedlen]='\0';
			}
			do {
#ifdef _DBG_
				printf("\n\n*+++++++++++++++++++++++*\n");
				printf("Parseando buffer de %i bytes\n",encodedlen);
				
#endif

				if (BytesToBeReaded <=0)
				{
#ifdef _DBG_
					printf("%s\n",encodedData);
					printf("\n\n*----------------*\n");
#endif
					if (encodedlen<=2) break;
					//printf("Bytes por leer: %i\n",BytesToBeReaded);
					if (ChunkNumber !=0) //Sobrepasamos el CLRF del principio
					{
						encodedData+=2;
						encodedlen-=2;
					}
					/* Read the next chunk Value (example 1337\r\n*/
					if (encodedlen>=MAX_CHUNK_LENGTH) {
						//memset(chunkcode,0,sizeof(chunkcode));
						memcpy(chunkcode,encodedData,MAX_CHUNK_LENGTH);
						chunkcode[MAX_CHUNK_LENGTH]='\0';
						p=strstr(chunkcode,"\r\n");
						if (!p){
#ifdef _DBG_
							//printf("Chunk encoding Error. Data chunk Format error %s\n",encodedData);
							printf("Chunk encoding Error. Data chunk Format error %s\n",chunkcode);
							printf("MORE: %s\n",encodedData);
							//exit(1);
#endif
							ChunkEncodeSupported = 0; //avoid further tests
							ConnectionClose=1; //ERRRORR!!!!
							free(TmpChunkData);
							TmpChunkData=NULL;
							break;
						}
					} else {
						memcpy(chunkcode,encodedData,encodedlen);
						chunkcode[encodedlen]='\0';
						p=strstr(chunkcode,"\r\n");
						if (!p) {
#ifdef _DBG_
							printf("Chunk encoding Error. Not enought data. Waiting for next chunk\n");
#endif
							if (ChunkNumber !=0) encodedlen+=2; //restauramos la longitud del chunk que vamos a analizar
							break;
						}
					}
					ChunkNumber++;
					*p='\0';
					chunk=strtol(chunkcode,NULL,16);
#ifdef _DBG_
					printf("Leido chunk de valor : %i\n",chunk);
#endif
					if (chunk==0) {
						BytesToBeReaded=0;
						break;
					}

					if ( (unsigned int) encodedlen >= 2 + strlen(chunkcode)+chunk) {
#ifdef _DBG_
						printf("Encodedlen (%i) >= 2 + strlen(chunkcode)+chunk\n",encodedlen);
#endif
						encodedlen-=2+chunk+strlen(chunkcode);
						//						printf("ahora quedan %i bytes\n");
						//printf("Exactamente: %s\n",encodedData);
						//encodedData+=2+chunk+strlen(chunkcode);
						BytesToBeReaded = -1;
						//memcpy(TmpChunkData,encodedData,encodedlen);
						//HACK: REVISAR SI FUNCIONA.
						memcpy(TmpChunkData,encodedData+2+chunk+strlen(chunkcode),encodedlen);

						encodedData=TmpChunkData;
						TmpChunkData[encodedlen]='\0';

					} else {
						encodedlen-=2 + (unsigned int)strlen(chunkcode);
						BytesToBeReaded = chunk - encodedlen;
						if (BytesToBeReaded == 0) BytesToBeReaded = -1;
						encodedlen=0;

#ifdef _DBG_
						printf("No llegan los datos: BytesToBeReaded asignado a %i\n",BytesToBeReaded);
#endif
					}
				} else {
#ifdef _DBG_
					printf("Tenemos un trozo de %i bytes . necesitamos %i bytes\n",encodedlen,BytesToBeReaded);
#endif
					if (encodedlen >= BytesToBeReaded)
					{

						encodedData+=BytesToBeReaded;
						encodedlen-=BytesToBeReaded;
						BytesToBeReaded=-1;
						memcpy(TmpChunkData,encodedData,encodedlen);
						TmpChunkData[encodedlen]='\0';
#ifdef _DBG_
						printf("Nos quedan %i bytes para seguir trabajando\n",encodedlen);
#endif
					} else {
						BytesToBeReaded -=encodedlen;
						encodedlen=0;
#ifdef _DBG_
						printf("Seguimos necesitando %i bytes\n",BytesToBeReaded);
#endif
					}
				}
			} while (encodedlen);
#ifdef _DBG_
			printf("Salimos del bucle\n");
#endif
		}


		if ( (ContentLength) && (read_size>0) )
		{
			BytesToBeReaded = ContentLength - BufferSize;
			//printf("se supone que BytesToBeReaded vale: %i\n",BytesToBeReaded);
			if (BytesToBeReaded < 0) {
#ifdef _DBG_
				printf("***********\nError leyendo..\n************\n");
#endif
				ConnectionClose = 1;
			}
		}
	}
#ifdef _DBG_
printf("End of reading\n");
if (response) {
	printf("Headers: %s\n",response->Header);
}
#endif


	/*** END OF READ LOOP **/

	if (!response) {
		/* Headers were not found. We can assume that non HTTPData have been returned. */
		response=InitHTTPData(NULL,NULL);
		if (lpBuffer) {
			free(response->Data);
			response->Data=lpBuffer;
			response->DataSize = BufferSize;
		}
	} else {
		if (HTTPIOMappingData)
		{
#ifdef __WIN32__RELEASE__
			WriteFile(HTTPIOMappingData->hTmpFilename,"\x00",1,&lpBufferSize,NULL);

			HTTPIOMappingData->hMapping = CreateFileMapping (HTTPIOMappingData->hTmpFilename,	NULL,	PAGE_READWRITE,	0,	BufferSize,NULL);
			if (HTTPIOMappingData->hMapping == 0)
			{
#ifdef _DBG_
				printf("error %i con %s %i\n",GetLastError(),HTTPIOMappingData->BufferedFileName,BufferSize);
				printf("%s\n",response->Header);
#endif
				return(NULL);
			} else {
				free(response->Data);
				response->Data =HTTPIOMappingData->BufferedPtr = (char*) MapViewOfFile (HTTPIOMappingData->hMapping , FILE_MAP_ALL_ACCESS, 0,0,0);
#ifdef _DBG_
				printf("Tenemos: %i bytes\n",BufferSize);
				printf("ptr1: %x\n",response->Data);
				printf("hemos asignado memoria: ptr: %x\n",HTTPIOMappingData->BufferedPtr);
				//for (int k=0;k<100;k++) printf("%c ",HTTPIOMappingData->BufferedPtr[k]);
				printf("%s\n",HTTPIOMappingData->BufferedPtr);
				
#endif
			}

#else
			//fwrite("\x00",1,1,HTTPIOMappingData->hTmpFilename);
			write(HTTPIOMappingData->hTmpFilename,"\x00",1);
			response->Data =HTTPIOMappingData->BufferedPtr = (char*) mmap (0, BufferSize +1, PROT_READ | PROT_WRITE, MAP_SHARED, HTTPIOMappingData->hTmpFilename, 0);
#endif
			response->DataSize = BufferSize;
		//printf("BUFEREADOS: %i bytes\n%s\n",response->DataSize, response->Data);
		}
}
if (TmpChunkData) free(TmpChunkData);

LockMutex(lock);
if (ConnectionClose) {
	FreeConnection(conexion);
} else {
	conexion->NumberOfRequests++;
	RemovePipeLineRequest(conexion);
	conexion->io = 0;
}
UnLockMutex(lock);

UnLockMutex(&conexion->lock);
/*
printf("HEMOS TARDADO: %i\n",((CurrentTime.tv_usec + CurrentTime.tv_sec*1000000) - (StartTime.tv_usec + StartTime.tv_sec*1000000) ) / 1000);
printf("Total: %i bytes\n",TotalSize);
*/
#ifdef _DBG_
printf("salimos de aqui..\n");
#endif
return (response);

}

/*******************************************************************************************/
//   ******************       HTTPCORE I/O PROTOCOL FUNCTIONS      **********************
/*******************************************************************************************/

/*******************************************************************************************/
//! This function stablishes a connection against a remote host
/*!
\param connection CONEXION struct returned by a previous call to GetSocketConnection
\return If the remote connection can be stablished, 1 is returned otherwise, an error is signaled with 0
*/
/*******************************************************************************************/
int StablishConnection(STABLISHED_CONNECTION *connection) {
	fd_set fds, fderr;
	struct timeval tv;

	connection->datasock = (int) socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	//memset(&connection->webserver, 0, sizeof(connection->webserver));
	connection->webserver.sin_family = AF_INET;
	connection->webserver.sin_addr.s_addr = connection->target;//inet_addr(target);
	connection->webserver.sin_port = htons(connection->port);
#ifdef __WIN32__RELEASE__
	u_long tmp=1;
	ioctlsocket( connection->datasock, FIONBIO, &tmp);
#else
	int tmp = 1;
	ioctl(connection->datasock, FIONBIO, (char *) &tmp);
#endif

	connection->NumberOfRequests = 0;
	connect(connection->datasock, (struct sockaddr *) &connection->webserver, sizeof(connection->webserver));
	tv.tv_sec = CONN_TIMEOUT;
	tv.tv_usec = 0;
	FD_ZERO(&fds);
	FD_ZERO(&fderr);
	FD_SET(connection->datasock, &fds);
	FD_SET(connection->datasock, &fderr);
	if (select((int) connection->datasock + 1, NULL,&fds, NULL,&tv) <= 0) {

#ifdef _DBG_
		printf("StablishConnection::Unable to connect Conexion %i to  (%s):%i\n",connection->id,inet_ntoa(connection->webserver.sin_addr),connection->port);
#endif
		closesocket(connection->datasock);
		return (0);
	}

#ifdef _DBG_
	printf("StablishConnection: Socket CONNECTED Conexion %i (%s:%i)\n",connection->id,inet_ntoa(connection->webserver.sin_addr),connection->port);

#endif
	if (connection->NeedSSL) {
#ifdef _OPENSSL_SUPPORT_
		int err=0;
		tmp=0;

#ifdef __WIN32__RELEASE__
		ioctlsocket( connection->datasock, FIONBIO, &tmp);
#else
		ioctl(connection->datasock, FIONBIO, (char *)&tmp);
#endif
		//SSL_load_error_strings();
		//SSL_library_init();
		connection->ctx = SSL_CTX_new(TLSv1_client_method()); //        ctx=SSL_CTX_new(SSLv2_client_method());
		if (!connection->ctx)
		{
#ifdef _DBG_
			printf("SSL_CTX_new failed\n");
#endif
			closesocket(connection->datasock);
			return 0;
		} 
#ifdef _DBG_
		else {
			printf("SSL_CTX_new ok\n");
		}
#endif
		connection->ssl=SSL_new(connection->ctx);
		SSL_set_fd(connection->ssl, connection->datasock);
		if ((err = SSL_connect(connection->ssl)) != 1)
		{
#ifdef _DBG_
			int newerr;
			newerr= SSL_get_error(connection->ssl,err);
			printf("SSL_connect failed: %s", strerror(errno));
			printf("SSLError: %i %i\n",newerr,err);
#endif
			SSL_shutdown(connection->ssl);
			SSL_free(connection->ssl);
			SSL_CTX_free(connection->ctx);
			closesocket(connection->datasock);
			return(0);
		}
		tmp=0;
#ifdef __WIN32__RELEASE__
		ioctlsocket( connection->datasock, FIONBIO, &tmp);
#else
		ioctl(connection->datasock, FIONBIO, (char *)&tmp);
#endif

#endif
	}
	return (1);

}
/*******************************************************************************************/
/*******************************************************************************************/

/*******************************************************************************************/
//   ******************       CONNECTION MANAGMENT FUNCTIONS       **********************
/*******************************************************************************************/

int InitFileMapping(void)
{
	InitMutex(&IoMappingLock);
	for (int i = 0; i< MAXIMUM_OPENED_HANDLES; i++) memset(&HTTPIoMappingData[i],0,sizeof (	HTTPIOMapping) );
	return(1);
}
/*******************************************************************************************/
int EndFileMapping(void)
{
	LockMutex(&IoMappingLock);
	for (int i = 0; i< MAXIMUM_OPENED_HANDLES; i++) {
		if (HTTPIoMappingData[i].assigned){
#ifdef __WIN32__RELEASE__
			CloseHandle(HTTPIoMappingData[i].hMapping);
			CloseHandle(HTTPIoMappingData[i].hTmpFilename);
#else
			close(HTTPIoMappingData[i].hTmpFilename);
#endif
			HTTPIoMappingData[i].assigned=0;
		}
	}
	UnLockMutex(&IoMappingLock);
	DeleteMutex(&IoMappingLock);
	return(1);

}
/*******************************************************************************************/
char *DeleteFileMapping(void* ptr)
{
	LockMutex(&IoMappingLock);
	for(int i=0;i<MAXIMUM_OPENED_HANDLES;i++)
	{
		if (HTTPIoMappingData[i].assigned)
		{
#ifdef _DBG_
			printf("encontrada entrada %i asignada verificando  %x con %x \n",i,ptr,HTTPIoMappingData[i].BufferedPtr);
#endif
			if (HTTPIoMappingData[i].BufferedPtr == ptr )
			{
				int ret;
				HTTPIoMappingData[i].assigned=0;
				//printf("LIBERANDO MEMORIA\n");

#ifdef __WIN32__RELEASE__
				ret = UnmapViewOfFile(HTTPIoMappingData[i].BufferedPtr);
				if (!ret) printf("UnmapViewOfFile Error: %i\n",GetLastError());
				ret = CloseHandle(HTTPIoMappingData[i].hMapping);
				if (ret==0) printf("CloseHandle1 Error: %i\n",GetLastError());

				ret= CloseHandle(HTTPIoMappingData[i].hTmpFilename);
				if (ret==0) printf("CloseHandle2 Error: %i (file %s)\n",GetLastError(),HTTPIoMappingData[i].BufferedFileName);
				//printf("Borrando Fichero: %s\n",HTTPIoMappingData[i].BufferedFileName);
				ret = DeleteFileA(HTTPIoMappingData[i].BufferedFileName);
				if (!ret) printf("DeleteFile Error: %i\n",GetLastError());
#else
				ret=munmap(HTTPIoMappingData[i].BufferedPtr,HTTPIoMappingData[i].MemoryLenght+1);
				if (ret==-1) printf("ERROR REMOVING MAPPING DATA\n");
				close(HTTPIoMappingData[i].hTmpFilename);
				remove(HTTPIoMappingData[i].BufferedFileName);
				//printf("Borrando: %s\n",HTTPIoMappingData[i].BufferedFileName);

#endif
				HTTPIoMappingData[i].MemoryLenght=0;
				UnLockMutex(&IoMappingLock);
				return (NULL);;
			}
		}
	}
	UnLockMutex(&IoMappingLock);
	return((char*)ptr);
}

/*******************************************************************************************/

PHTTPIOMapping GetFileMapping(unsigned int DataSize, char *lpData )
{
	LockMutex(&IoMappingLock);

	for(int i=0;i<MAXIMUM_OPENED_HANDLES;i++)
	{
		if (!HTTPIoMappingData[i].assigned)
		{
			char szTmpFile[256];
			HTTPIoMappingData[i].assigned=1;
			HTTPIoMappingData[i].BufferedPtr = NULL;
			UnLockMutex(&IoMappingLock);

#ifdef __WIN32__RELEASE__
			GetTempPathA (256, szTmpFile);
			GetTempFileNameA (szTmpFile, "FHScan",0,HTTPIoMappingData[i].BufferedFileName);
#ifdef _DBG_
			printf("Usando fichero temporal: %s\n",HTTPIoMappingData[i].BufferedFileName);
#endif
			HTTPIoMappingData[i].hTmpFilename = CreateFileA ( HTTPIoMappingData[i].BufferedFileName,
				GENERIC_WRITE | GENERIC_READ,
				FILE_SHARE_WRITE,
				NULL,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_TEMPORARY,
				NULL);
			if ( HTTPIoMappingData[i].hTmpFilename == INVALID_HANDLE_VALUE) {
#ifdef _DBG_
				printf("GetFileMapping Error: Unable to create temporary filename\n");
#endif
				HTTPIoMappingData[i].assigned= 0;
				return(NULL);
			}

#else
			strcpy(HTTPIoMappingData[i].BufferedFileName,tempnam(NULL,"FHScan") );
			//printf("\ncreando: %s\n",HTTPIoMappingData[i].BufferedFileName);
			HTTPIoMappingData[i].hTmpFilename  = open(HTTPIoMappingData[i].BufferedFileName,O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif
			//		printf("hTmpFilename = %i\n",HTTPIoMappingData[i].hTmpFilename);

			if (DataSize){
#ifdef __WIN32__RELEASE__
				HTTPIoMappingData[i].hMapping = CreateFileMapping (HTTPIoMappingData[i].hTmpFilename,
					NULL,
					PAGE_READWRITE,
					0,
					DataSize,
					NULL);
				if (!HTTPIoMappingData[i].hMapping) {
#ifdef _DBG_
					printf("GetFileMapping Error: Unable to create file mapping\n");
					return(NULL);
#endif

				}
#endif
				if (lpData)
				{
#ifdef __WIN32__RELEASE__
					DWORD lpBufferSize;
					WriteFile(HTTPIoMappingData[i].hTmpFilename,(unsigned char*)lpData,DataSize,&lpBufferSize,NULL);
#else
					write(HTTPIoMappingData[i].hTmpFilename,lpData,DataSize);
					//fwrite(lpData,DataSize,1,HTTPIoMappingData[i].hTmpFilename);

#endif
				}
			}
			return ( &HTTPIoMappingData[i] );
		}
	}
	UnLockMutex(&IoMappingLock);
	printf(" ** CRITICAL ERROR**  NOT ENOUGHT FREE FILEHANDLES. Maybe you forget to call FreeRequest() up to %i times\n",MAXIMUM_OPENED_HANDLES);
	return ( (PHTTPIOMapping) NULL);
}
/*******************************************************************************************/


/*******************************************************************************************/

