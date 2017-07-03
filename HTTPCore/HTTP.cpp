/** \file HTTP.cpp
 * Fast HTTP Auth Scanner -  HTTP Public / Exported API functions
*/

/*
 * TODO:
 * Revisar el soporte de proxy HTTP con autenticacion ("Proxy-Authorization" + "Proxy-Authenticate")
 * Implementation of the AutoRedirect303 feature (y mirar que hacer con 302 y 301 )
 * Segregar SendHTTPRequest() en BuildHTTPRequest() y despues una llamada a DispatchHTTPRequest(). 
   Esto permitiría definir un SendAsyncHTTPRequest() y definir un Callback para la petición.
*/

#include "HTTPCore.h"
#include "CallBack.h"
#include "Threading.h"



/*******************************************************************************
 ************************** Functions not exported *****************************
 *******************************************************************************/

static char*		GetServerVersion(HTTP_DATA *response);
static unsigned int	IschallengeSupported(char *headers);
static PREQUEST 	ParseReturnedBuffer(HTTPHANDLE HTTPHandle, PHTTP_DATA request, PHTTP_DATA response, char *url);

/*******************************************************************************
 *************************** Local definitions to this module ******************
 *******************************************************************************/
unsigned int AutoRedirect303		 = 1;
const char	 UserAgent[]			 = "User-Agent: Mozilla/5.0 (FHScan Core 1.1)\r\n";
PHHANDLE	 GlobalHTTPCoreApiOptions = NULL;

/*******************************************************************************/
/************************** GLOBAL HTTP CORE FUNCTIONS *************************/
/*******************************************************************************/
//! Initializes the HTTP Core. You must call InitHTTPApi before interacting with HTTP functions.
/*!
	\return This functions returns 1 Initialization succes. Value 2 means that the API is already initialized and 0 that there is a critical error.
*/
/*******************************************************************************/
int		InitHTTPApi(void)
{
	if (!GlobalHTTPCoreApiOptions)
	{
		int ret = InitHTTPApiCore();
		if ( ret == 1 )
		{
			GlobalHTTPCoreApiOptions = (PHHANDLE)malloc(sizeof(struct _hhandle));
			memset((void*)GlobalHTTPCoreApiOptions,0,sizeof(struct _hhandle));
		}
		return (ret);
	} else return (2);
}
/*******************************************************************************/
//! This function is used to stop working with HTTP Core. Previous call to InitHTTPApi() is required.
/*******************************************************************************/
void	CloseHTTPApi(void)
{
	CloseHTTPApiCore();
	if (GlobalHTTPCoreApiOptions)
	{
		free(GlobalHTTPCoreApiOptions);
		GlobalHTTPCoreApiOptions = NULL;
	}
	CloseHTTPConnectionHandle((HTTPHANDLE)GlobalHTTPCoreApiOptions);
	GlobalHTTPCoreApiOptions = NULL;
}
/*******************************************************************************/
//! This function is used to set global configuration options for each connection
/*!
	/param opt This value indicates the kind of data that is going to be modified. Valid options are
	OPT_HTTP_PROXY_HOST, OPT_HTTP_PROXY_PORT, OPT_HTTP_PROXY_USER,OPT_HTTP_PROXY_PASS, OPT_HTTP_PROXY_HEADER, OPT_HTTP_COOKIE, OPT_HTTP_USERAGENT, OPT_HTTP_PROXY_PROTOCOL
	/parameter Pointer to the option data.
*/
/*******************************************************************************/
int SetHTTPAPIConfig(int opt, char *parameter)
{
	return(SetHTTPConfig(GlobalHTTPCoreApiOptions,opt,parameter));
}
/*******************************************************************************/
//! This function retrieves the current global configuration
/*!
	/param opt This value indicates the kind of data that is going to be retrieved. Valid options are
	OPT_HTTP_PROXY_HOST, OPT_HTTP_PROXY_PORT, OPT_HTTP_PROXY_USER,OPT_HTTP_PROXY_PASS, OPT_HTTP_PROXY_HEADER, OPT_HTTP_COOKIE, OPT_HTTP_USERAGENT, OPT_HTTP_PROXY_PROTOCOL
	/return Pointer to the option data.
*/
/*******************************************************************************/
char *GetHTTPAPIConfig( int opt)
{
	return(GetHTTPConfig(GlobalHTTPCoreApiOptions,opt));
}
/*******************************************************************************/
//! This function returns a pseudo-Handle needed to stablish an HTTP connection. This information is managed internally by the HTTP Core. Only one call is required for handling each remote host.
/*!
	\param hostname Pointer to the remote hostname. This value can be either an ip address or a hostname
	\param port TCP port for the remote HTTP Server.
	\param ssl Boolean parameter (values 1 or 0 ) to identify if the remote http server port requires an HTTPS connection
	\note This function does not stablish HTTP Connections, only internal data is initialized. Call SetHTTPConfig() for more features.
	\note The configuration for this handle is inherit from global options defined at SetHTTPAPIConfig().

 \code
 HTTPHANDLE connection=InitHTTPConnectionHandle("mail.google.com",443,1);
 if (connection)
 {
	...
 }
 \endcode
 */
 /*******************************************************************************/
HTTPHANDLE InitHTTPConnectionHandle(char *hostname, int port, int ssl)
{
	PHHANDLE HTTPHandle=NULL;
	struct sockaddr_in remote;

	remote.sin_addr.s_addr = inet_addr(GlobalHTTPCoreApiOptions->ProxyHost ? GlobalHTTPCoreApiOptions->ProxyHost : hostname);
	if (remote.sin_addr.s_addr == INADDR_NONE)
	{
		struct hostent *hostend=gethostbyname(GlobalHTTPCoreApiOptions->ProxyHost ? GlobalHTTPCoreApiOptions->ProxyHost : hostname);
		if (!hostend)
		{
			return((HTTPHANDLE)NULL);
		}
		memcpy(&remote.sin_addr.s_addr, hostend->h_addr, 4);
	}
	HTTPHandle=(PHHANDLE)malloc(sizeof(struct _hhandle));
	memset(HTTPHandle,0,sizeof(struct _hhandle));
	HTTPHandle->target=remote.sin_addr.s_addr;
	strncpy(HTTPHandle->targetDNS, hostname ,sizeof(HTTPHandle->targetDNS));
	//printf("resuelto %s como %s\n",hostname,inet_ntoa(remote.sin_addr));
	HTTPHandle->port			= port;
	HTTPHandle->NeedSSL			= ssl;
	HTTPHandle->version			= 1;
	HTTPHandle->AdditionalHeader= GlobalHTTPCoreApiOptions->AdditionalHeader ? _strdup(GlobalHTTPCoreApiOptions->AdditionalHeader) : NULL;
	HTTPHandle->UserAgent		= GlobalHTTPCoreApiOptions->UserAgent ? _strdup(GlobalHTTPCoreApiOptions->UserAgent) : NULL;
	HTTPHandle->ProxyHost		= GlobalHTTPCoreApiOptions->ProxyHost ? _strdup(GlobalHTTPCoreApiOptions->ProxyHost): NULL;
	HTTPHandle->ProxyPort		= GlobalHTTPCoreApiOptions->ProxyPort ? _strdup(GlobalHTTPCoreApiOptions->ProxyPort): NULL;
	HTTPHandle->lpProxyUserName = GlobalHTTPCoreApiOptions->lpProxyUserName ? _strdup(GlobalHTTPCoreApiOptions->lpProxyUserName): NULL;
	HTTPHandle->lpProxyPassword = GlobalHTTPCoreApiOptions->lpProxyPassword ? _strdup(GlobalHTTPCoreApiOptions->lpProxyPassword): NULL;
	HTTPHandle->DownloadBwLimit = GlobalHTTPCoreApiOptions->DownloadBwLimit ? _strdup(GlobalHTTPCoreApiOptions->DownloadBwLimit): NULL; 
	HTTPHandle->Cookie			= NULL;
	HTTPHandle->conexion		= NULL;
	HTTPHandle->LastAuthenticationString=NULL;
	memset(HTTPHandle->LastRequestedUri,'\0',sizeof(HTTPHandle->LastRequestedUri));
	#ifdef _DBG_
	printf("resuelto %s como %s\n",hostname,inet_ntoa(remote.sin_addr));
	#endif
	
#ifdef __WIN32__RELEASE__
	HTTPHandle->ThreadID = GetCurrentThreadId();
#else
	HTTPHandle->ThreadID = pthread_self();
#endif

	return((HTTPHANDLE)HTTPHandle);

}
/*******************************************************************************/
//! This function allows users to retrieve HTTP Configuration parameters.
/*!
	\param HTTPHandle pointer to a handle returned by a previous call to InitHTTPConnectionHandle()
	\param opt this value indicates the kind of data that is going to be modified. Valid options are
	OPT_HTTP_PROXY_HOST, OPT_HTTP_PROXY_PORT, OPT_HTTP_PROXY_USER,OPT_HTTP_PROXY_PASS, OPT_HTTP_PROXY_HEADER, OPT_HTTP_COOKIE, OPT_HTTP_USERAGENT, OPT_HTTP_PROXY_PROTOCOL
	\return NULL terminated pointer to specific parameter string.
*/
/*******************************************************************************/

char *GetHTTPConfig(HTTPHANDLE HTTPHandle,int opt)
{
	PHHANDLE phandle=(PHHANDLE)HTTPHandle;
	switch(opt)
	{
		case OPT_HTTP_MAXSPEED_DOWNLOAD:
			return(NULL);
			break;
		case OPT_HTTP_COOKIE:
			return ( phandle->Cookie );
			break;
		case OPT_HTTP_HEADER:
			return ( phandle->AdditionalHeader );
			break;
		case OPT_HTTP_USERAGENT:
			return ( phandle->UserAgent);
			break;
		case OPT_HTTP_PROXY_HOST:
			return ( phandle->ProxyHost);
			break;
		case OPT_HTTP_PROXY_PORT:
			return(phandle->ProxyPort);
			break;
		case OPT_HTTP_PROXY_USER:
			return ( phandle->lpProxyUserName );
			break;
		case OPT_HTTP_PROXY_PASS:
			return ( phandle->lpProxyPassword );
			break;
		case OPT_HTTP_PROTOCOL:
			return(NULL);
			break;
	}
	return(NULL);
}
/*******************************************************************************/
//! This function Allows users to change some HTTP request parameters.
/*!
	\param HTTPHandle pointer to a handle returned by a previous call to InitHTTPConnectionHandle()
	\param opt this value indicates the kind of data that is going to be modified. Valid options are
	OPT_HTTP_PROXY_HOST, OPT_HTTP_PROXY_PORT, OPT_HTTP_PROXY_USER,OPT_HTTP_PROXY_PASS, OPT_HTTP_PROXY_HEADER, OPT_HTTP_COOKIE, OPT_HTTP_USERAGENT, OPT_HTTP_PROXY_PROTOCOL
	\param parameter pointer to the header that will be included in the http request.
	\return This function returns 1 if operation succed, otherwhise -1 is returned.
	\note if parameter is NULL or an empty string, the stored data is erased for that option.
	\code

 HTTPHANDLE connection = InitHTTPConnectionHandle("mail.google.com",443,1);
 if (connection)
 {
	SetHTTPConfig(connection,OPT_HTTP_USERAGENT,"FHScan Core API client");
	PREQUEST DATA = SendHTTPRequest(connection,"GET","/index.html",NULL,NULL,NO_AUTH);
	if (DATA) {
		printf("Returned Headers: %i bytes\n %s\n",DATA->response->HeaderSize,DATA->response->Header);
		printf("Returned Data: %i bytes\n %s\n",DATA->response->DataSize,DATA->response->Data);

		FreeRequest(DATA);
	}
	SetHTTPConfig(connection,OPT_HTTP_USERAGENT,NULL);
	//...
 }
 \endcode
*/

/*******************************************************************************/

int SetHTTPConfig(HTTPHANDLE HTTPHandle,int opt, char *parameter)
{
	PHHANDLE phandle=(PHHANDLE)HTTPHandle;
	if (!HTTPHandle) return(-1);

	switch (opt)
	{

	 case OPT_HTTP_MAXSPEED_DOWNLOAD:
		 if (phandle->DownloadBwLimit) free(phandle->DownloadBwLimit);
		 if (parameter)
		 {			 
			 phandle->DownloadBwLimit = _strdup(parameter);
		 } else {
			 phandle->DownloadBwLimit = NULL;
		 }

		break;
	 case OPT_HTTP_COOKIE:
		 if ( (parameter) && (*parameter) ){
			if (phandle->Cookie)
			{
				free(phandle->Cookie);
				phandle->Cookie= NULL;
			}
			if (strnicmp(parameter,"Cookie: ",8)==0) //Validate the cookie parameter
			{
				phandle->Cookie=_strdup(parameter);
			} else //Add Cookie Header..
			{
				phandle->Cookie=(char*)malloc( 8 + strlen(parameter) +1 );
				strcpy(phandle->Cookie,"Cookie: ");
				strcpy(phandle->Cookie+8,parameter);
			}
		 } else {
			 if (phandle->Cookie)
			 {
				free(phandle->Cookie);
				phandle->Cookie = NULL;
			 }
		 }
		break;

	 case OPT_HTTP_HEADER:
		 if (phandle->AdditionalHeader) 
		 {
			 free(phandle->AdditionalHeader);			
		 }
		 if ( (parameter) && (*parameter) && (strchr(parameter,':')) ) 
		 {
			 int len2 = (int) strlen(parameter);
			 if (memcmp(parameter+len2 -2,"\r\n",2)!=0) {
				 phandle->AdditionalHeader = (char*)malloc(len2 +2 +1 );
				 memcpy(phandle->AdditionalHeader,parameter,len2);
				 memcpy(phandle->AdditionalHeader +len2,"\r\n\x00",3);
			 } else {
				phandle->AdditionalHeader = _strdup(parameter);
			}
		 }  else {
			 phandle->AdditionalHeader=NULL;
		 }
		break;

	 case OPT_HTTP_USERAGENT:
		 if (phandle->UserAgent) {
			free(phandle->UserAgent);
		 }
		 if (parameter) {			
			phandle->UserAgent= _strdup(parameter);
		} else {
				phandle->UserAgent=NULL;
		}
		break;
	 case OPT_HTTP_PROXY_HOST:
		if (phandle->ProxyHost) {
			free(phandle->ProxyHost);
			phandle->ProxyHost=NULL;
		}
		phandle->NeedSSL=0;
		if (parameter) {
			struct sockaddr_in remote;
			phandle->ProxyHost=_strdup(parameter);
			remote.sin_addr.s_addr = inet_addr(phandle->ProxyHost);
			if (remote.sin_addr.s_addr == INADDR_NONE)
			{
				struct hostent *hostend=gethostbyname(phandle->ProxyHost);
				if (!hostend) return(-1);
				memcpy(&remote.sin_addr.s_addr, hostend->h_addr, 4);
			}
			phandle->target=remote.sin_addr.s_addr;
		} else  {
			struct sockaddr_in remote;
			phandle->ProxyHost = NULL;
			remote.sin_addr.s_addr = inet_addr(phandle->targetDNS);
			if (remote.sin_addr.s_addr == INADDR_NONE)
			{
				struct hostent *hostend=gethostbyname(phandle->targetDNS);
				if (!hostend) return(-1);
				memcpy(&remote.sin_addr.s_addr, hostend->h_addr, 4);
			}
			phandle->target=remote.sin_addr.s_addr;
		}
		phandle->conexion=NULL;
		if (!phandle->ProxyPort) phandle->ProxyPort=_strdup("8080");
		break;

	 case OPT_HTTP_PROXY_PORT:
		if (parameter) {
			if (phandle->ProxyPort) free(phandle->ProxyPort);
			phandle->ProxyPort=_strdup(parameter);
		} else {
			free(phandle->ProxyPort);
			phandle->ProxyPort=NULL;
		}
		break;

	 case OPT_HTTP_PROXY_USER:
    	if (phandle->lpProxyUserName) {
			free(phandle->lpProxyUserName);
		}
		if (parameter) {
			phandle->lpProxyUserName=_strdup(parameter);
		} else phandle->lpProxyUserName=NULL;
		break;

	 case OPT_HTTP_PROXY_PASS:
		if (phandle->lpProxyPassword) {
			free(phandle->lpProxyPassword);
		}
		if (parameter) {
			phandle->lpProxyPassword=_strdup(parameter);
		} else phandle->lpProxyPassword=NULL;
		break;

	 case OPT_HTTP_PROTOCOL:
		if (parameter) {
			phandle->version=atoi(parameter);
		} else phandle->version=1;
        break;
	 default:
    	return(-1);

	}
    return(1);

}
/*******************************************************************************/
//! This function destroys an HTTP Handle.
/*!
	\param HTTPHandle Pointer to the Handle returned by InitHTTPConnectionHandle(). This value cant be NULL
	\note Be sure to close the connection handle to avoid memory leaks
*/
/*******************************************************************************/
void CloseHTTPConnectionHandle(HTTPHANDLE HTTPHandle){
	if (HTTPHandle) {
		if ((((PHHANDLE)HTTPHandle)->DownloadBwLimit)) free((((PHHANDLE)HTTPHandle)->DownloadBwLimit));
		if ((((PHHANDLE)HTTPHandle)->ProxyHost)) free((((PHHANDLE)HTTPHandle)->ProxyHost));
		if ((((PHHANDLE)HTTPHandle)->ProxyPort)) free((((PHHANDLE)HTTPHandle)->ProxyPort));
		if ((((PHHANDLE)HTTPHandle)->AdditionalHeader)) free((((PHHANDLE)HTTPHandle)->AdditionalHeader));
		if ((((PHHANDLE)HTTPHandle)->UserAgent)) free((((PHHANDLE)HTTPHandle)->UserAgent));
		if ((((PHHANDLE)HTTPHandle)->lpProxyUserName)) free((((PHHANDLE)HTTPHandle)->lpProxyUserName));
		if ((((PHHANDLE)HTTPHandle)->lpProxyPassword)) free((((PHHANDLE)HTTPHandle)->lpProxyPassword));
		if ((((PHHANDLE)HTTPHandle)->LastAuthenticationString)) free((((PHHANDLE)HTTPHandle)->LastAuthenticationString));
		free(HTTPHandle);
	}
}

/*******************************************************************************/
//! This function search for the "Server:" Header at a server response.
/*!
	\param response pointer to an HTTP_DATA struct that stores the data returned  by the http server.
	\return  GetServerVersion() allocates memory and returns the remote server version. If the remote server header is not found "HTTP/1.0" is returned instead.
*/
/*******************************************************************************/
static char *GetServerVersion(HTTP_DATA *response){
	char *server=NULL;
	if (response)
	{
		if (response->Header)
		{
			if (response->HeaderSize)
			{
				server = GetHeaderValue(response->Header,"Server: ",0);
				if ((!server) && (response->HeaderSize>=12) )
				{
					//server=(char*)malloc(9);
					//sprintf(server,"HTTP/1.%c",response->Header[7]);
					//TODO: IMPLEMENT THIS IN NEXT RELEASE
				}
			}

		}
	}
	return( server ? server :_strdup("HTTP/1.0") );
}
/*****************************************************************************/
 //! This function enumerates all valid authentication schemes supported by the remote http resource.
/*!
	\param headers pointer to an string that contains the remote server verbs. Normally HTTPDATARESPONSE->Header
	\return supported authentication schemes, valid values are: BASIC_AUTH, DIGEST_AUTH , NTLM_AUTH  , UNKNOWN_AUTH , NO_AUTH
	\note If several Authentication schemes are supported BASIC_AUTH and NTLM_AUTH are prefered instead of DIGEST_AUTH or NEGOTIATE_AUTH.
*/
/*****************************************************************************/
static unsigned int IschallengeSupported(char *headers)
{
  char *AuthNeeded="WWW-Authenticate:";
  unsigned int ret=0;
  int i=0;
  char *auth;

  do {
    auth=GetHeaderValue(headers,AuthNeeded,i++);
	if (auth) {
		if (strnicmp (auth, "basic",  5) == 0) {
		   if (!(ret & BASIC_AUTH)) ret+=BASIC_AUTH;
		}  else
		if (strnicmp (auth, "digest", 6) == 0) {
		   if (!(ret & DIGEST_AUTH)) ret+=DIGEST_AUTH;
		} else
		if (strnicmp (auth, "ntlm",   4) == 0) {
		   if (!(ret & NTLM_AUTH)) ret+=NTLM_AUTH;
		} else
		if (strnicmp (auth, "Negotiate",   9) == 0) {
		   if (!(ret & NTLM_AUTH)) ret+=NEGOTIATE_AUTH;
        } else {
	       if (!(ret & UNKNOWN_AUTH)) ret+=UNKNOWN_AUTH;
		}
		free(auth);
	}
  } while (auth) ;

  if (ret & BASIC_AUTH) 	return(BASIC_AUTH);
  if (ret & DIGEST_AUTH) 	return(DIGEST_AUTH);
  if (ret & NTLM_AUTH) 		return(NTLM_AUTH);
  if (ret & NEGOTIATE_AUTH) return(NEGOTIATE_AUTH);

  return(ret);
}


/*******************************************************************************/
//! This function generates and fills a REQUEST struct with the HTTP request and response information.
/*!
	\param HTTPHandle HANDLE to the remote HTTP Server.
	\param request pointer to an HTTP_DATA struct that contains the request information sent to a remote HTTP Server
	\param response pointer to an HTTP_DATA struct that contains the response information received from a remote HTTP Server.
	\param url pointer to the string that contains the url path requested by the client.
	\return pointer to an allocated REQUEST struct. If the HTTP Response is not present NULL will be returned instead.
	\note The struct generated by this function will be returned to the user.
*/
/*******************************************************************************/
static PREQUEST ParseReturnedBuffer(HTTPHANDLE HTTPHandle, PHTTP_DATA request, PHTTP_DATA response, char *url)
{
	PHHANDLE RealHTTPHandle=(PHHANDLE)HTTPHandle;
	struct _request *data;
	char version[4];
	if (!response)
	{
		FreeHTTPData(request);
		return(NULL);
	}
	data=(struct _request*)malloc(sizeof(struct _request));
	memset((void*)data,'\0',sizeof(struct _request));
	strncpy(data->hostname,RealHTTPHandle->targetDNS,sizeof(data->hostname)-1);
	data->ip=RealHTTPHandle->target;
	data->port=RealHTTPHandle->port;
	data->NeedSSL = RealHTTPHandle->NeedSSL;
	data->request=request;
	data->response=response;
	data->server=GetServerVersion(response);
	if (response->HeaderSize>=12)
	{
		memcpy(version,response->Header+9,3);
		version[3]='\0';
		data->status=atoi(version);
	}
	data->challenge=IschallengeSupported(response->Header);

    if (data->challenge & DIGEST_AUTH)
    {
		if (RealHTTPHandle->LastAuthenticationString){
			free(RealHTTPHandle->LastAuthenticationString);
			RealHTTPHandle->LastAuthenticationString=NULL;
		}
		RealHTTPHandle->LastAuthenticationString=GetHeaderValue(response->Header,"WWW-Authenticate: Digest ",0);
	}

	strncpy(data->url,url,sizeof(data->url)-1);
	strncpy(((PHHANDLE)HTTPHandle)->LastRequestedUri,url,sizeof(((PHHANDLE)HTTPHandle)->LastRequestedUri));

	return(data);
}
/*******************************************************************************/
 //! This function is used to securely append data to a buffer.
/*******************************************************************************/
static __inline void AddLine(char *lpBuffer, char *source, unsigned int *Buffersize)
{
    strncat(lpBuffer,source,*Buffersize);
	*Buffersize-=(unsigned int)strlen(source);
}
/*******************************************************************************/
//! This function is used to get a header returned by the HTTP server by using the header name.
/*!
	\param headers Pointer to an string containing the headers returned by The server. You should use request->header here
	\param value pointer to an string containing the search header. Example char *value = "Location:"
	\param n Number of matching headers to be searched.
	\return GetHeaderValue() returns a Pointer to a string ended by '\\0' that contains the header provided by the remote HTTP server. This function returns NULL if the header is not found.
	\note spaces at the beginning of the return value are removed.
	\note The returned buffer does not contain the ending "\r\n". Is user task to free the memory allocated by this function. Example:
	\code
	struct _request *data;
	...
	char *buffer=GetHeaderValue(data->response->header,"Location:",0);
	if (buffer)
	{
		printf("[+] Found redirect to: %s\n",buffer);
		free(buffer);
	}

	\endcode
 */
/*******************************************************************************/
char *GetHeaderValue(char *headers,char *value,int n)
{
    char *base,*end;
    end=base=headers;
    if ( (headers) && (value) )
	{
    	unsigned int valuelen= (unsigned int) strlen(value);
        while (*end) {
            if (*end=='\n')
			{
				if (strnicmp(base,value,valuelen)==0)
                {
					if (n==0)
                    {
                        base  = base + valuelen;
                        while  (*base==' ') { base++; }
						int len = end-base;
						//assert(end-base < 1024 );
						char *header=(char*)malloc(len+1);
						memcpy(header,base,len);
						if (header[len-1]=='\r')
						{
							header[len-1]='\0';
						} else {
							header[len]='\0';
						}
						return (header);
                    } else
                    {
                        n--;
                    }
                }
				base=end+1;
            }
			end++;
        }
    }
    return(NULL);
}
/*******************************************************************************/
//! This function is used to get a header returned by the HTTP server.
/*!
	\param headers Pointer to an string containing the headers returned by The server. You should use request->header here
	\param id Header id referecence for matching the header. For example id 0 is the first header (usually like "GET /resource HTTP/1.0\r\n")
	\return GetHeaderValueByID() returns a Pointer to a string ended by '\\0' that contains the header provided by the remote HTTP server. This function returns NULL if there are less headers than the value specified by the id parameter.
	\note The returned buffer does not contain the ending "\r\n". Is user task to free the memory allocated by this function. Example:
	\code
	struct _request *data;
	char *buffer=NULL;
	int id=0;
	...
	while (1)
	{
		buffer=GetHeaderValue(data->response->header,"Location:",id);
		if (buffer != NULL)
		{
			printf("Header[%3.3i]: %s\n",id,buffer);
			free(buffer);
			id++;
		} else {
			break;
		}
	}
	\endcode
 */
/*******************************************************************************/
char *GetHeaderValueByID(char *headers, unsigned int id)
{
	char *base, *end;
	base = end=headers;

	#define HEADER_ID_NOT_FOUND NULL

   if (headers)
	{
		while (*end)
		{
			if  (*end=='\n')
			{
				if (id==0)
				{
					if ( (end - base)==1) {
                    	return(HEADER_ID_NOT_FOUND);
					}
					char *p=(char *) malloc(end - base +1);
					memcpy(p,base,end-base);
					p[end-base]='\0';
					if (p[end-base-1]=='\r')
						p[end-base-1]='\0';
					return(p);
				}
				id--;
				base=end+1;
			}
			end++;
		}
	}
	return (HEADER_ID_NOT_FOUND);
}
/*******************************************************************************/
//!This function adds a header to the request
/*!
        \param request PHTTP_DATA pointer to the headers
        \param Header Null terminated pointer to the string that is going to be added.
        \note Headers MUST contain \\r\\n at the end
*/
/*******************************************************************************/
PHTTP_DATA AddHeader(PHTTP_DATA request,char *Header)
{
	int NewSize= (int) strlen(Header);

	request->Header=(char*)realloc(request->Header, request->HeaderSize + NewSize +1);
	memcpy(request->Header + request->HeaderSize -2, Header,NewSize);
	memcpy(request->Header + request->HeaderSize -2 + NewSize,"\r\n",2);
	request->HeaderSize+=NewSize;
	request->Header[request->HeaderSize]='\0';

    return(request);

}

/*******************************************************************************/
//! This function Searches a PHTTP_DATA structure for specific headers and if found , the header is removed
/*!
	\param request PHTTP_DATA pointer to the headers
	\param Header Null Terminated pointer to the string that is going to be removed.
*/
/*******************************************************************************/
PHTTP_DATA RemoveHeader(PHTTP_DATA request, char *Header)
{
	char *base,*end;
	base = end=request->Header;

	if ( (request) && (request->Header) && (Header) )
	{
        int HeaderLen= (int) strlen(Header);
		while (*end) {
			if (*end=='\n')
			{
				if (strnicmp(base,Header,HeaderLen)==0)
				{
					end=strchr(base,'\n');
					memcpy(request->Header + (base - request->Header),end+1,strlen(end+1)+1);
					request->Header=(char *)realloc(request->Header,request->HeaderSize - (end - base +1) +1 );
					request->HeaderSize = (int) strlen(request->Header);//request->HeaderSize - (end - base -1) ;
					break;
				}
				base=end+1;
			}
			end++;
		}
	}
	return(request);

}
/*******************************************************************************/
//! This function destroys a _request struct returned by SendHttpRequest() and free reserved memory
/*!
	\param data Pointer to a _request struct
	\return FreeRequest() This function always returns a NULL pointer
	\note Be sure to close the _request struct to avoid memory leaks
 */
/*******************************************************************************/
void *FreeRequest(PREQUEST data) {
   if (data)
   {
       FreeHTTPData(data->request);
       FreeHTTPData(data->response);
	  if (data->server) free(data->server);
      free(data);
   }
   return(NULL);
}
/*******************************************************************************/
//! This function is used by the user to send an special crafted HTTP Request against a webserver.
/*!
   \param HTTPHandle HANDLE that identifies the remote HTTP Host. This handle is returned by InitHTTPConnectionHandle()
   \param headers pointer to a null terminated string that contains the headers sent to the HTTP Server. This string must end with "\r\n\r\n" to avoid HTTP errors.
   \param postdata pointer to an optional string containing additional data (like POST data)
   \return a Pointer to a _request struct is returned with information of the http response.
   \note This function returns NULL if the remote connection cant be stablished

/*******************************************************************************/
PREQUEST SendRawHttpRequest(HTTPHANDLE HTTPHandle,char *headers, char *postdata)
{
	PREQUEST 		DATA;
	PHTTP_DATA		request,response;

	request=InitHTTPData(headers,postdata);
	response=DispatchHTTPRequest((PHHANDLE)HTTPHandle,request);
	DATA=ParseReturnedBuffer( HTTPHandle, request,response,"/TODO"); //manually parse the request buffer to extract URI

	return(DATA);
}
/*******************************************************************************/
//! This function is used by the user to send a request against a webserver
/*!
   \param HTTPHandle HANDLE that identifies the remote HTTP Host. This handle is returned by InitHTTPConnectionHandle()
   \param VHost Alternate VHost for the http request. This value will be send in the "Host:" header instead of the ip address. This value can be NULL
   \param HTTPMethod Pointer to the HTTP verb that will be send in the request. Examples "GET", "POST", "HEAD","OPTIONS",
   \param url Pointer to the url. Example "/index.html"
   \param Postdata Optional data to be send in the request. For example "login=user&pass=mypassword"
   \param lpUsername Pointer to an optional username. This value is used if the remote host needs an username for authentication. (error 401)
   \param lpPassword Pointer to an optional password. This value is used if the remote host needs password for authentication.    (error 401)
   \param AuthMethod This value specifies the authentication scheme. If the value is NO_AUTH (0) lpUsername and lpPassword are ignored.
   \return a Pointer to a _request struct is returned with information of the http response.
   \note SendHttpRequest() is only able to handle NTLM and digest authentication when running under win32.
   This function returns NULL if the remote connection cant be stablished

	\code
#include "http.h"


int test(char *hostname, int port, int sslNeeded)
{
 struct _request *data,*newdata;
 HTTPHANDLE HTTPHandle=InitHTTPConnectionHandle(hostname,port,sslNeeded);
 if (!HTTPHandle)
 {
	 printf("[-] InitHTTPConnectionHandle() Error. Unable to resolve %s\n",hostname);
	 return(0);
 }

  data=SendHttpRequest(HTTPHandle,hostname,"GET","/admin/",NULL,NULL,NULL,NO_AUTH);
  if (!data)
  {
	  printf("[-] SendHttpRequest() Error. Unable to connect to %s:%i\n",hostname,port);
	  CloseHTTPConnectionHandle(HTTPHandle);
	  return(0);
  }
  if (data->status==401)
  {
		newdata=SendHttpRequest(HTTPHandle,hostname,"GET","/admin/",NULL,"user","password",data->challenge);
		if (newdata)
		{
			printf("[+] Status: %i\n",newdata->status);
			for(int i=0;i<newdata->nheaders,i++)
			{
				printf("[+] Header(%i): %s\n",i,newdata->header[i]);

			}
			printf("[+] Data: %s\n",newdata->lpBuffer);
			FreeRequest(newdata);
		}
  }
  CloseHTTPConnectionHandle(HTTPHandle);
  FreeRequest(data);
  return(1);
}


void main(int argc, char *argv[])
{

	InitHTTPApi();
	test("www.tarasco.org",80,0);
	CloseHTTPApi();
}
\endcode
*/
/*******************************************************************************/
PREQUEST SendHttpRequest(
	HTTPHANDLE HTTPHandle,
	char *VHost,
	char *HTTPMethod,
	char *url,
	char *Postdata,
	char *lpUsername,
	char *lpPassword,
	int AuthMethod)
{
	char    		tmp[MAX_POST_LENGHT+1]="";
	char    		lpBuffer[MAX_POST_LENGHT+1]="";
	unsigned int   	lpSize=MAX_POST_LENGHT;
	PREQUEST 		DATA;
	PHHANDLE 		RealHTTPHandle=(PHHANDLE)HTTPHandle;
	PHTTP_DATA 		request=NULL, response=NULL;// = InitHTTPData();

	if ( (!url) || (*url=='\0') ){ //Bad url
		return ( NULL);
	}

	if ( (RealHTTPHandle->ProxyHost) && (!RealHTTPHandle->NeedSSL) )
	{
        snprintf(lpBuffer,lpSize-1,"%s http://%s:%i%s HTTP/1.%i\r\n",HTTPMethod,RealHTTPHandle->targetDNS,RealHTTPHandle->port,url,((PHHANDLE)HTTPHandle)->version);
	} else
	{
		if ( (strncmp(HTTPMethod,"GET",3)!=0) || (!Postdata) || (!*Postdata) ) {
			snprintf(lpBuffer,lpSize-1,"%s %s HTTP/1.%i\r\n",HTTPMethod,url,((PHHANDLE)HTTPHandle)->version);
		} else {
			snprintf(lpBuffer,lpSize-1,"GET %s?%s HTTP/1.%i\r\n",url,Postdata,((PHHANDLE)HTTPHandle)->version);
		}
	}
	lpSize-=(unsigned int)strlen(lpBuffer);

	if (VHost) 	{
		snprintf(tmp,sizeof(tmp)-1,"Host: %s\r\n",VHost);
	} else {
		snprintf(tmp,sizeof(tmp)-1,"Host: %s\r\n",((PHHANDLE)HTTPHandle)->targetDNS);
	}
	AddLine(lpBuffer,tmp,&lpSize);

	if (RealHTTPHandle->UserAgent) {
		AddLine(lpBuffer,RealHTTPHandle->UserAgent,&lpSize);
	} else {
		AddLine(lpBuffer,(char*)UserAgent,&lpSize);
	}

	if (RealHTTPHandle->AdditionalHeader) {
		AddLine(lpBuffer,RealHTTPHandle->AdditionalHeader,&lpSize);
	}
	if (RealHTTPHandle->Cookie) {
		sprintf(tmp,"%s\r\n",RealHTTPHandle->Cookie);
		AddLine(lpBuffer,tmp,&lpSize);
	}

	if (RealHTTPHandle->ProxyHost) {
		AddLine(lpBuffer,"Proxy-Connection: keep-alive\r\n",&lpSize);
	} else {
		AddLine(lpBuffer,"Connection: keep-alive\r\n",&lpSize);
	}


	if  (  (strncmp(HTTPMethod,"GET",3)!=0) && (Postdata) && (*Postdata) )
	{
		snprintf(tmp,sizeof(tmp)-1,"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %i\r\n",strlen(Postdata));
		AddLine(lpBuffer,tmp,&lpSize);
	}


	if ( (AuthMethod) && (lpUsername) && (lpPassword) )
	{
		struct _request *tmpdata=NULL;
//        char *tmpdataBuffer;
        switch (AuthMethod)
        {
            case BASIC_AUTH:
			    char RawUserPass[750];
			    char EncodedUserPass[1000];
			    snprintf(RawUserPass,sizeof(RawUserPass),"%s:%s",lpUsername,lpPassword);
			    memset(EncodedUserPass,'\0',sizeof(EncodedUserPass));
			    Base64Encode((unsigned char *)EncodedUserPass,(unsigned char*)RawUserPass,(int)strlen(RawUserPass));
			    snprintf(tmp,sizeof(tmp)-1,"Authorization: Basic %s\r\n",EncodedUserPass);
                AddLine(lpBuffer,tmp,&lpSize);
                break;
            case DIGEST_AUTH:
			    //Search for cached nonce in memory.
			    char *AuthenticationHeader;
			    if ( (*RealHTTPHandle->LastRequestedUri) && (strcmp(RealHTTPHandle->LastRequestedUri,url)==0) && (RealHTTPHandle->LastAuthenticationString!=NULL) )
			    {
				    //printf("Reusing realm: %s\n",RealHTTPHandle->LastAuthenticationString );
			    } else
				{
					//Send another request to check if authentication is required and get www-authenticate header
					char     tmplpBuffer[MAX_POST_LENGHT+1];
					unsigned int    tmplpSize=lpSize;
					strncpy(tmplpBuffer,lpBuffer,sizeof(tmplpBuffer)-1);

					//Append end of request CLRF
					strncat(tmplpBuffer,"\r\n",tmplpSize);tmplpSize-=2;

					if  (  (strncmp(HTTPMethod,"GET",3)!=0) && (Postdata) )//Add optional POST HEADER
					{
						AddLine(tmplpBuffer,Postdata,&lpSize);
						//strncat(tmplpBuffer,Postdata,lpSize);
					}
					request=InitHTTPData(tmplpBuffer,NULL);
					response=DispatchHTTPRequest((PHHANDLE)HTTPHandle,request);
					tmpdata=ParseReturnedBuffer( HTTPHandle, request,response,url);//, tmpdataBuffer,ReturnedDataSize);
					if (!tmpdata) return(NULL);

					if (tmpdata->status!=401) {
						return(tmpdata);
					}
					if (RealHTTPHandle->LastAuthenticationString) free(RealHTTPHandle->LastAuthenticationString);
					RealHTTPHandle->LastAuthenticationString=GetHeaderValue(tmpdata->response->Header,"WWW-Authenticate: Digest ",0);
				}

			    AuthenticationHeader=CreateDigestAuth(RealHTTPHandle->LastAuthenticationString,lpUsername,lpPassword,HTTPMethod,url,0);
				if (AuthenticationHeader)
				{

					FreeRequest(tmpdata);
					tmpdata=NULL;
					memset(tmp,'\0',sizeof(tmp));
					strncpy(tmp,AuthenticationHeader,sizeof(tmp)-1); free(AuthenticationHeader);
					AddLine(lpBuffer,tmp,&lpSize);
				} else
				{
#ifdef _DBG_
					sprintf(tmp,"AUTH DIGEST FAILED Host %s - path: %s, DATA:%s\n",RealHTTPHandle->targetDNS,url,RealHTTPHandle->LastAuthenticationString);
					printf("%s\n",tmp);
#endif
                    if (RealHTTPHandle->LastAuthenticationString) {
                        free(RealHTTPHandle->LastAuthenticationString);
                        RealHTTPHandle->LastAuthenticationString=NULL;
                    }
					//return(tmpdata);
			    }

                break;
            case NTLM_AUTH:
            case NEGOTIATE_AUTH:
			    unsigned char buf2[4096];
			    unsigned char buf1[4096];
			    char     tmplpBuffer[MAX_POST_LENGHT+1];
			    unsigned int tmplpSize=lpSize;
			    strncpy(tmplpBuffer,lpBuffer,sizeof(tmplpBuffer)-1);
                #ifdef _DBG_
				sprintf(tmp,"path: %s - host: %s\n",url,RealHTTPHandle->targetDNS);
			                printf("DBG: %s\n",tmp);
                #endif
			    memset(buf1,'\0',sizeof(buf1));
			    memset(buf2,'\0',sizeof(buf2));

                //NTLM message type 1
			    BuildAuthRequest((tSmbNtlmAuthRequest*)buf2,0,NULL,NULL);

                #ifdef _DBG_
                    printf("CLIENT MSG1\n");
//                    DumpMem(buf2,SmbLength((tSmbNtlmAuthResponse*)buf2));
                #endif
			    to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthResponse*)buf2));
			    snprintf(tmp,sizeof(tmp)-1,"Authorization: NTLM %s\r\n",buf1);

			    //Append authorization header
			    strncat(tmplpBuffer,tmp,tmplpSize);
			    tmplpSize-=(unsigned int)strlen(tmp);

			    //Append end of request CLRF
			    AddLine(tmplpBuffer,"\r\n",&tmplpSize);

				//Add optional POST HEADER
			    if  (  (strncmp(HTTPMethod,"GET",3)!=0) && (Postdata) )
			    {
				    strncat(tmplpBuffer,Postdata,lpSize);
			    }
			    //Send Initial Request
                #ifdef _DBG_
			                printf("ENVIANDO: %s\n",tmplpBuffer);
                #endif
				request=InitHTTPData(tmplpBuffer,NULL);
				response=DispatchHTTPRequest((PHHANDLE)HTTPHandle,request);
			    tmpdata=ParseReturnedBuffer( HTTPHandle, request,response,url);

			    if (!tmpdata)  return(NULL);

				if (tmpdata->status==401)
			    {
				    //Parse NTLM Message Type 2
	//                tmpdata->response
					char *response=GetHeaderValue(tmpdata->response->Header,"WWW-Authenticate: NTLM ",0);
					if (!response) {
                    #ifdef _DBG_
						printf("WWW-Authenticate: NTLM Header not Found\n");
					#endif
					    strncpy(tmpdata->url,url,sizeof(tmpdata->url)-1);
                        //tmpdata->url=_strdup(url);
					    return(tmpdata);
				    }
				    //Build NTLM Message Type 3
                    #ifdef _DBG_
				                    printf("Obtenido: !%s!\n",response);
                    #endif
				    from64tobits((char *)&buf1[0], response);

                    #ifdef _DBG_
                        printf("SERVER MSG2\n");
//                        DumpMem(buf1,0x100);
                        dumpAuthChallenge(0,(tSmbNtlmAuthChallenge*)buf1);
                    #endif
				    buildAuthResponse((tSmbNtlmAuthChallenge*)buf1,(tSmbNtlmAuthResponse*)buf2,0,lpUsername,lpPassword,NULL,NULL);
                    #ifdef _DBG_
                        printf("CLIENT MSG3\n");
//                        DumpMem(buf2,SmbLength((tSmbNtlmAuthResponse*)buf2));
                    #endif

				    to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthResponse*)buf2));
				    snprintf(tmp,sizeof(tmp)-1,"Authorization: NTLM %s\r\n",buf1);
                    #ifdef _DBG_
                        printf("Enviando: !%s!",tmp);
                    #endif
				    free(response);
					//tmpdata=
					FreeRequest(tmpdata);
			    } else {
				    //strcpy(tmpdata->hostname,((PHHANDLE)HTTPHandle)->hostname);
					//strncpy(tmpdata->url,url,sizeof(tmpdata->url));
				    return(tmpdata);
				}
                AddLine(lpBuffer,tmp,&lpSize);
				break;
			}
	}



	strncat(lpBuffer,"\r\n",lpSize);
	lpSize-=2;

	request=InitHTTPData(lpBuffer,NULL);
	//Optional Post Data
	if  (  (strncmp(HTTPMethod,"GET",3)!=0) && (Postdata) ) {
    	free(request->Data);
		request->Data=_strdup(Postdata);
		request->DataSize= (unsigned int) strlen(Postdata);
	}

	response=DispatchHTTPRequest(RealHTTPHandle,request);

	DATA=ParseReturnedBuffer(RealHTTPHandle, request, response, url);

	if ( (!AuthMethod) && (lpUsername) && (lpPassword) && (DATA) && (DATA->challenge))
	{
		#ifdef _DBG_
		printf("**********REAUTH**********\n");
		#endif
		struct _request *AUTHDATA=SendHttpRequest(
			HTTPHandle,
			VHost,
			HTTPMethod,
			url,
			Postdata,
			lpUsername,
			lpPassword,
			DATA->challenge);
		if (AUTHDATA)
		{
			FreeRequest(DATA);
			return(AUTHDATA);
		}
	}

	/*
	if (DATA) {
		if ( (DATA->status==303) && (AutoRedirect303) && (DATA->response) && (DATA->response->HeaderSize) )  {
            char *location= GetHeaderValue(DATA->response->Header,"Location: ",1);
			if (location) {
				if (*location) {
					char Redirecthost[1000];
					unsigned int Redirectport;
					char RedirectURL[1000];
					int ssl;
					if ( (Redirectport == RealHTTPHandle->port) && (RealHTTPHandle->NeedSSL == ssl) ) {

					}

					FreeRequest(DATA);
					DATA =SendHttpRequest(
						HTTPHandle,
						Redirecthost,
						"GET",
						RedirectURL,
						NULL,
						lpUsername,
						lpPassword,
						DATA->challenge);
				}

				free(location);
			}

		}
	}

	*/
 /*
	if (DATA->challenge)
	{
		if (lpUsername) strncpy(DATA->lpUserName,lpUsername,sizeof(DATA->UserName)-1);
		if (lpPassword) strncpy(DATA->lpPassword,lpPassword,sizeof(DATA->Password)-1);
	}
*/
    return(DATA);
}
/*******************************************************************************************/
//! This function is used to disconnect a currently stablished connection.
/*!
\param HTTPHandle Handle of the remote connection.
\param what Cancel only the current request HTTP_REQUEST_CURRENT or blocks all connections against the remote HTTP host with HTTP_REQUEST_ALL.
\note This function is needed to cancel requests like example a CONNECT call sent against a remote 
HTTP proxy server by SendRawHttpRequest()
*/
/*******************************************************************************************/
int CancelHttpRequest(HTTPHANDLE HTTPHandle, int what)
{
	return ( HTTPCoreCancelHTTPRequest(HTTPHandle, what));
}
/*******************************************************************************************/