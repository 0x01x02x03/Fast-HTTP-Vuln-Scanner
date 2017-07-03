#ifndef __HTTPCORE__
#define __HTTPCORE__
#include "Build.h"
#include "HTTP.h"
#include "Authentication/base64.h"
#include "Authentication/ntlm.h"
#include "Authentication/digest.h"

#ifdef __WIN32__RELEASE__
 #include <sys/timeb.h>
 #include <process.h>
 #include <time.h>
 #include <wininet.h>
 //#pragma comment(lib, "ws2_32.lib")
#else
 #include <stdlib.h>
 #include <unistd.h>
 #include <fcntl.h>
 #include <sys/socket.h>
 #include <sys/ioctl.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <pthread.h>
 #include <ctype.h>
 #include <time.h>
 #include <sys/timeb.h>
 #define FILETIME time_t
#endif

#ifdef _OPENSSL_SUPPORT_

 #include <openssl/crypto.h>
 #include <openssl/x509.h>
 #include <openssl/pem.h>
 #include <openssl/ssl.h>
 #include <openssl/err.h>
/*
 #ifdef __WIN32__RELEASE__
	#pragma comment(lib, "libeay32MT.lib")
  	#pragma comment(lib, "ssleay32MT.lib")
 #endif
 */
#endif



/******************************************************************************/

#define MAX_OPEN_CONNECTIONS					512 //Our Connection table is able to handle 512 concurrent connections
#define PURGETIME								20  //20 secconds
#define MAX_OPEN_CONNETIONS_AGAINST_SAME_HOST	10  //Do not allow more concurrent connections against the same server/port
#define BUFFSIZE								4096 //default read buffer
#define TARGET_FREE   							0
#define MAX_INACTIVE_CONNECTION 				10000000 *PURGETIME
#define MAXIMUM_OPENED_HANDLES					1024

/******************************************************************************/

/* Internal struct for HANDLING FILEMAPPINGS */

typedef struct _HTTPmapping_struct_
{
   int			   assigned;
   char			  *BufferedPtr;
   unsigned long   MemoryLenght;
   char			   BufferedFileName[MAX_PATH];
  #ifdef __WIN32__RELEASE__
   HANDLE		   hTmpFilename;
   HANDLE          hMapping;
  #else
   int			  hTmpFilename;
  #endif
} HTTPIOMapping, *PHTTPIOMapping;

/****************************************************************************/
/* Internal struct for Handling Connections */
typedef struct conexiones {
	long 		target;
	char 		targetDNS[256];
	int 		port;
	int 		NeedSSL;
	unsigned int datasock;
	struct sockaddr_in webserver;
	#ifdef _OPENSSL_SUPPORT_
	SSL_CTX *	ctx;
	SSL *		ssl;
	#endif
	FILETIME 	tlastused;
	CRITICAL_SECTION lock; //avoid pipelining
	unsigned int 		NumberOfRequests;
	unsigned int 		io;
	int         PENDING_PIPELINE_REQUESTS;
	PHTTP_DATA *PIPELINE_Request;
	unsigned long *PIPELINE_Request_ID;
	int 		id;
	unsigned int BwLimit;
#ifdef __WIN32__RELEASE__
	int			ThreadID;
#else
	pthread_t   ThreadID;
#endif
	int ConnectionAgainstProxy;
	int ProxyMethod;
} STABLISHED_CONNECTION;

/******************************************************************************/
/*!\struct _hhandle
  \brief This struct is the information used by FHScan to manage HTTP requests.
  This struct does not manage sockets, however a pointer to an STABLISHED_CONNECTION is provided.
  For the user point of view, this handle is only a pointer. an user must not tweak data stored in this struct.
*/
typedef struct _hhandle{
	long 		target;
	char 		targetDNS[256];
	int  		port;
#ifdef __WIN32__RELEASE__
	int			ThreadID;
#else
	pthread_t   ThreadID;
#endif
	int 		NeedSSL;
	int 		version;
	char	   *AdditionalHeader;
	char 	   *Cookie;
	char 	   *UserAgent;
	char	   *DownloadBwLimit;
	STABLISHED_CONNECTION *conexion; //Pointer to last used connection
	char 		LastRequestedUri[512];
	char 	   *LastAuthenticationString;
	char 	   *ProxyHost;
	char 	   *ProxyPort;
	char 	   *lpProxyUserName;
	char 	   *lpProxyPassword;
} *PHHANDLE;

/******************************************************************************/
int						HTTPCoreCancelHTTPRequest(HTTPHANDLE HTTPHandle, int what);
void 					FreeConnection(STABLISHED_CONNECTION *connection);
static void 		   *CleanConnectionTable(void *foo);
static unsigned int 	GetNumberOfConnectionsAgainstTarget(PHHANDLE HTTPHandle);
static int 				GetFirstIdleConnectionAgainstTarget(PHHANDLE HTTPHandle);
static int 				GetFirstUnUsedConnectionAgainstTarget(PHHANDLE HTTPHandle);
int 					RemovePipeLineRequest(STABLISHED_CONNECTION *connection);
static unsigned long 	AddPipeLineRequest(STABLISHED_CONNECTION *connection, PHTTP_DATA request);
static STABLISHED_CONNECTION *GetSocketConnection(PHHANDLE HTTPHandle, PHTTP_DATA request, unsigned long *id);
PHTTP_DATA 				DispatchHTTPRequest(PHHANDLE HTTPHandle,PHTTP_DATA request);
int 					InitHTTPApiCore(void);
void 					CloseHTTPApiCore(void);
PHTTP_DATA 				InitHTTPData(char *header, char *postdata);
void 					FreeHTTPData(HTTP_DATA *data);
/******************************************************************************/

#endif

