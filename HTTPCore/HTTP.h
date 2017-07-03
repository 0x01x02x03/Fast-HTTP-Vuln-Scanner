/** \file HTTP.h
 * Fast HTTP Auth Scanner - HTTP Engine.
 * This include file contains all needed information to manage the HTTP interface from the user side.
 * \author Andres Tarasco Acuna - http://www.tarasco.org
 */
#ifndef __HTTPAPI__
#define __HTTPAPI__


#ifndef __AFXISAPI_H_ // these symbols may come from WININET.H
//! OK to continue with request
#define HTTP_STATUS_CONTINUE            100
//! server has switched protocols in upgrade header
#define HTTP_STATUS_SWITCH_PROTOCOLS    101
//! request completed
#define HTTP_STATUS_OK                  200
//! object created, reason = new URI
#define HTTP_STATUS_CREATED             201
//! async completion (TBS)
#define HTTP_STATUS_ACCEPTED            202
//! partial completion
#define HTTP_STATUS_PARTIAL             203
//! no info to return
#define HTTP_STATUS_NO_CONTENT          204
//! request completed, but clear form
#define HTTP_STATUS_RESET_CONTENT       205
//! partial GET furfilled
#define HTTP_STATUS_PARTIAL_CONTENT     206
//! server couldn't decide what to return
#define HTTP_STATUS_AMBIGUOUS           300
//! object permanently moved
#define HTTP_STATUS_MOVED               301
//! object temporarily moved
#define HTTP_STATUS_REDIRECT            302
//! redirection w/ new access method
#define HTTP_STATUS_REDIRECT_METHOD     303
//! if-modified-since was not modified
#define HTTP_STATUS_NOT_MODIFIED        304
//! redirection to proxy, location header specifies proxy to use
#define HTTP_STATUS_USE_PROXY           305
//! HTTP/1.1: keep same verb
#define HTTP_STATUS_REDIRECT_KEEP_VERB  307
//! invalid syntax
#define HTTP_STATUS_BAD_REQUEST         400
//! access denied
#define HTTP_STATUS_DENIED              401
//! payment required
#define HTTP_STATUS_PAYMENT_REQ         402
//! request forbidden
#define HTTP_STATUS_FORBIDDEN           403
//! object not found
#define HTTP_STATUS_NOT_FOUND           404
//! method is not allowed
#define HTTP_STATUS_BAD_METHOD          405
//! no response acceptable to client found
#define HTTP_STATUS_NONE_ACCEPTABLE     406
//! proxy authentication required
#define HTTP_STATUS_PROXY_AUTH_REQ      407
//! server timed out waiting for request
#define HTTP_STATUS_REQUEST_TIMEOUT     408
//! user should resubmit with more info
#define HTTP_STATUS_CONFLICT            409
//! the resource is no longer available
#define HTTP_STATUS_GONE                410
//! the server refused to accept request w/o a length
#define HTTP_STATUS_LENGTH_REQUIRED     411
//! precondition given in request failed
#define HTTP_STATUS_PRECOND_FAILED      412
//! request entity was too large
#define HTTP_STATUS_REQUEST_TOO_LARGE   413
//! request URI too long
#define HTTP_STATUS_URI_TOO_LONG        414
//! unsupported media type
#define HTTP_STATUS_UNSUPPORTED_MEDIA   415
//! internal server error
#define HTTP_STATUS_SERVER_ERROR        500
//! required not supported
#define HTTP_STATUS_NOT_SUPPORTED       501
//! error response received from gateway
#define HTTP_STATUS_BAD_GATEWAY         502
//! temporarily overloaded
#define HTTP_STATUS_SERVICE_UNAVAIL     503
//! timed out waiting for gateway
#define HTTP_STATUS_GATEWAY_TIMEOUT     504
//! HTTP version not supported
#define HTTP_STATUS_VERSION_NOT_SUP     505
#define HTTP_STATUS_FIRST               HTTP_STATUS_CONTINUE
#define HTTP_STATUS_LAST                HTTP_STATUS_VERSION_NOT_SUP
#endif



/******************************************************************************/
/*!\struct _data
  \brief This struct stores information to an HTTP request or response. Both HTTP Headers and HTTP body data are stored under this struct.
*/
typedef struct _data {
	char *Header;
    /*!< Pointer to a null terminated string that stores the HTTP Headers. */
	unsigned int HeaderSize;
    /*!< Size of the HTTP Headers. */
	char *Data;
    /*!< Pointer to a null terminated string that stores the HTTP Data. */
	unsigned int DataSize;
    /*!< Size of the HTTP Data. */
} HTTP_DATA, *PHTTP_DATA;


/*!\struct _request
  \brief This struct handles information related to and http response and includes information about client request, server response, url, server version .returned by an HTTP Server
*/
typedef struct _request {
	char hostname[256];
   /*!< hostname of the server. This is related to the vhost parameter. If no vhost is specified, hostname contains the ip address. */
   int ip;
   /*!< remote HTTP ip address. */
   int port;
   /*!< remote HTTP port. This value is obtained from the InitHTTPConnectionHandle() */
   int NeedSSL;
   /*!< Boolean value. If this parameter is 1 then the connection is handled by openssl otherwise is just a tcp connection */
   char url[512];
   /*!< path to the file or directory requested */
   PHTTP_DATA request;
   /*!< Information related to the HTTP Request. This struct contains both client headers and postdata */
   PHTTP_DATA response;
   /*!< Information related to the HTTP response. This struct contains both server headers and data */
   char *server;
   /*!< pointer to a string that contains the server banner from the remote http server */
   unsigned int 	 status;
   /*!< status code returned by the HTTP server. Example: "200", for an STATUS OK response. */
   unsigned int challenge;  //Authentication type
   /*!< This value is not Zero if the remote host require authentication by returning the http header "WWW-Authenticate:" Possible values are: NO_AUTH,  BASIC_AUTH , DIGEST_AUTH, NTLM_AUTH, UNKNOWN_AUTH.*/
} REQUEST, *PREQUEST;

/*! \fn typedef void* HTTPHANDLE
 *  For the user, this pseudo-handle returned by InitHTTPConnectionHandle() is just a pointer.

 */
typedef void* HTTPHANDLE;

/******************************************************************************/

#define NO_AUTH			0
#define BASIC_AUTH		1
#define DIGEST_AUTH		2
#define NTLM_AUTH		4
#define NEGOTIATE_AUTH	8
#define UNKNOWN_AUTH	16

#define MAX_POST_LENGHT 	4096
#define MAX_DOWNLOAD_SIZE 	MAX_POST_LENGHT*20


#define OPT_HTTP_PROXY_HOST		0x00
#define OPT_HTTP_PROXY_PORT		0x01
#define OPT_HTTP_PROXY_USER		0x02
#define OPT_HTTP_PROXY_PASS		0x04

#define OPT_HTTP_HEADER			0x08
#define OPT_HTTP_COOKIE			0x10
#define OPT_HTTP_USERAGENT		0x20
#define OPT_HTTP_PROTOCOL		0x40
#define OPT_HTTP_MAXSPEED_DOWNLOAD	0x80

//#define OPT_HTTP_USERNAME		0x100
//#define OPT_HTTP_PASSWORD		0x200

//#define OPT_APPEND_PARAMETER 0x40000000

/******************************************************************************/
/* CancelHttpRequest() options */
#define HTTP_REQUEST_CURRENT 1
#define HTTP_REQUEST_ALL	 0

/******************************************************************************/
/* Global API Initialization Functions*/
int					InitHTTPApi( void );
void				CloseHTTPApi( void) ;
int					SetHTTPAPIConfig( int opt, char *parameter );
char			   *GetHTTPAPIConfig( int opt );

/* Handle creation */
HTTPHANDLE 			InitHTTPConnectionHandle( char *hostname,int port,	int ssl );
int 				SetHTTPConfig( HTTPHANDLE HTTPHandle,	int opt,	char *parameter );
char			   *GetHTTPConfig( HTTPHANDLE HTTPHandle,	int opt);
void				CloseHTTPConnectionHandle( HTTPHANDLE HTTPHandle);

/* HTTP Request forgering */
PREQUEST 			SendHttpRequest(	HTTPHANDLE HTTPHandle,  char *Vhost,    char *HTTPMethod,char *url,char *Postdata,char *lpUsername,char *lpPassword,int AuthMethod);
PREQUEST 			SendRawHttpRequest(	HTTPHANDLE HTTPHandle,char *headers, char *postdata);
void				*FreeRequest(		PREQUEST request);
int					CancelHttpRequest(HTTPHANDLE HTTPHandle, int what);

/* Header Manipulation */
char*				GetHeaderValue(char *headers,char *value,int n);
char*				GetHeaderValueByID(char *headers, unsigned int id);
PHTTP_DATA 			RemoveHeader(PHTTP_DATA request, char *Header);
PHTTP_DATA AddHeader(PHTTP_DATA request,char *Header);



#endif
