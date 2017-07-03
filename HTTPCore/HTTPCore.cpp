/* TODO: 

* En la tabla de conexiones hacer referencia al hostname no solo al ipaddress, para evitar problemas con hosts que resuelven varias dns
****
El acceso a FreeRequest (para gestionar la estructura CONEXION) se realiza siempre bloqueando el mutex "LOCK".
Dado que FreeRequest() intenta reconectar, muchos threads pueden quedar bloqueados. 
Revisar si el lock se debe realizar dentro de la propia funcion.
****

/** \file HTTPCore.cpp
* FHScan HTTP Core Library
* Most of This functions are not exported and should not be called outside this file.
* Do not modify this functions unless you know what are you doing =).
*/

#include "IoFunctions.h"
#include "Threading.h"
#include "CallBack.h"
#include "Modules/Encoding_Chunked.h"
#ifdef _ZLIB_SUPPORT_
#include "Modules/Encoding_Deflate.h"
#endif

#ifdef __WIN32__RELEASE__
static HANDLE 			FreeConnectionHandle;
#else
static pthread_t FreeConnectionHandle;
#endif
static STABLISHED_CONNECTION *Connection_Table=NULL;
static 					CRITICAL_SECTION lock;
unsigned long 			PIPELINE_Request_ID;


/*******************************************************************************************/
//! This function is used to clean the connection struct and cancel I/O request.
/*!
\param HTTPHandle Handle of the remote connection.
\param what Cancel only the current request HTTP_REQUEST_CURRENT or blocks all connections against the remote HTTP host with HTTP_REQUEST_ALL.
\note This function is needed when for example a CONNECT call is sent against a remote HTTP proxy server.
*/
/*******************************************************************************************/
int HTTPCoreCancelHTTPRequest(HTTPHANDLE HTTPHandle, int what)
{
 PHHANDLE phandle = (PHHANDLE)HTTPHandle;
 int ret=0;
 LockMutex(&lock);
 if (phandle->conexion)
 {
	 shutdown(phandle->conexion->datasock,2);
	 closesocket(phandle->conexion->datasock);
	 phandle->conexion->NumberOfRequests=what;
	 ret=1;
 }
 UnLockMutex(&lock);
 return (ret);
}



/*******************************************************************************************/
//! This function is used to clean the status of a connection struct when the conexion socket is closed or when there is a problem reading the HTTP stream (like timeouts). 
/*!
\param connection Pointer to a CONEXION struct
\note All the internal counters are reset and the first pipelined request is removed.
\note If there are pending pipelined requests this function will also reconnect the socket and send those requests to the server
*/
/*******************************************************************************************/
void FreeConnection(STABLISHED_CONNECTION *connection) {
#ifdef _DBG_
	printf("++++++++++++++++ FreeConnection( %i requests pending) +++++++++++\n",connection->PENDING_PIPELINE_REQUESTS);
	for(int i=0;i< connection->PENDING_PIPELINE_REQUESTS; i++)
	{
		printf("REQUEST: %s\n",  connection->PIPELINE_Request[i]->Header);
	}
#endif

	RemovePipeLineRequest(connection);

#ifdef _DBG_

	/*
	for(int i=0;i< connection->PENDING_PIPELINE_REQUESTS; i++)
	{
	printf("++++++++++++++++ FreeConnection( %i requests pending) +++++++++++\n",connection->PENDING_PIPELINE_REQUESTS);
	printf("REQUEST2: %s\n",  connection->PIPELINE_Request[i]->Header);
	}  	*/
#endif
	
#ifdef _OPENSSL_SUPPORT_
	if (connection->NeedSSL)
	{
		SSL_shutdown(connection->ssl);
		SSL_free(connection->ssl);
		SSL_CTX_free(connection->ctx);
	}
#endif
	shutdown(connection->datasock,2);
	closesocket(connection->datasock);
	connection->NumberOfRequests=0;
	connection->io=0;
#ifdef __WIN32__RELEASE__
	connection->tlastused.dwHighDateTime=0;
	connection->tlastused.dwLowDateTime=0;
	//if (connection->)
#else
	connection->tlastused=0;
#endif

	if (connection->PENDING_PIPELINE_REQUESTS) {
#ifdef _DBG_
		printf("LLAMANDO A STABLISH CONNECTION desde FreeConnection\n"); 
#endif
		connection->io=1;
		int i = StablishConnection(connection);
		if (i) {
			for (i = 0; i < connection->PENDING_PIPELINE_REQUESTS; i++) {
				SendHTTPRequestData(connection,connection->PIPELINE_Request[i]);
			}
		} else {
			/* TODO 1 : Que pasa si no podemos reconectar... COMO SE GESTIONAN los errores... */	
#ifdef _DBG_
			printf("ERROR UNABLE TO RECONNECT\n");
#endif

		}
	} else {
		connection->target=TARGET_FREE;
		connection->port=TARGET_FREE;
		connection->NeedSSL=TARGET_FREE;
	}
	connection->io=0;
}
/*******************************************************************************************/
//! This function analyzes and cleans the internal connection table every 5 seconds. All inactive connections are purged.
/*!
\param unused unused (added for compatibility with win32 CreateThread function).
\note this function is only used internally by HTTPCore Module.
\note The connections are threated as inactive if the connection is unused for more than MAX_INACTIVE_CONNECTION seconds. This value can be modified in the source code.
\note The connection must have the io flag inaactive (not in use).
*/
/*******************************************************************************************/
static void *CleanConnectionTable(void *unused)
{

#ifdef __WIN32__RELEASE__
	FILETIME fcurrenttime;
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER LastUsedTime;
#else
	time_t fcurrenttime;
#endif
	while(1)
	{

		LockMutex(&lock);

#ifdef __WIN32__RELEASE__
		GetSystemTimeAsFileTime(&fcurrenttime);
		CurrentTime.LowPart=fcurrenttime.dwLowDateTime;
		CurrentTime.HighPart=fcurrenttime.dwHighDateTime;
#else
		time(&fcurrenttime);
#endif
		for(int i=0; i<MAX_OPEN_CONNECTIONS;i++)
		{
			if ( (Connection_Table[i].target!=TARGET_FREE) && (!Connection_Table[i].io) && (!Connection_Table[i].PENDING_PIPELINE_REQUESTS) )
			{
				//TODO: El recurso .io deberia estar protegido por el mutex de conexion[i].lock ?
#ifdef __WIN32__RELEASE__
				LastUsedTime.HighPart= Connection_Table[i].tlastused.dwHighDateTime;
				LastUsedTime.LowPart= Connection_Table[i].tlastused.dwLowDateTime;
				if ( (CurrentTime.QuadPart - LastUsedTime.QuadPart) > MAX_INACTIVE_CONNECTION ) {
#else
				if ( (fcurrenttime -Connection_Table[i].tlastused)> MAX_INACTIVE_CONNECTION )  {
#endif

#ifdef _DBG_
					printf("DBG: Eliminando conexion %3.3i against %s:%i \n",i,Connection_Table[i].targetDNS,Connection_Table[i].port);
#endif
					FreeConnection(&Connection_Table[i]);
				}
			}
		}

		UnLockMutex(&lock);

#ifdef __WIN32__RELEASE__
		Sleep(5000);
#else
		sleep(5);
#endif
	}
}
#if 0
/*******************************************************************************************/
//! This function checks how many connections are stablished against the same remote host/port service.
/*!
\param HTTPHandle Connection handle.
\return Returns the number of currently stablished connections against the remote host.
\note This function is only used internally by HTTPCore Module.
*/
/*******************************************************************************************/
static unsigned int GetNumberOfConnectionsAgainstTarget(PHHANDLE HTTPHandle)
{
	int n=0;
	for(unsigned int i=0;i<MAX_OPEN_CONNECTIONS;i++)
	{
		if ( (Connection_Table[i].target==HTTPHandle->target) && (Connection_Table[i].port==HTTPHandle->port) )
		{
			n++;
		}
	}
	return(n);
}
#endif
/*******************************************************************************************/
//! This function checks the connection table searching for a free and inactive connection against the remote host.
/*!
\param HTTPHandle Connection handle.
\return Returns an index to the CONEXION item in the connection table.
\note This function is only used internally by HTTPCore Module.
\note If no connection matches, -1 is returned.
*/
/*******************************************************************************************/
static int GetFirstIdleConnectionAgainstTarget(PHHANDLE HTTPHandle)
{
	for(unsigned int i=0;i<MAX_OPEN_CONNECTIONS;i++)
	{
		if ( (Connection_Table[i].ThreadID==HTTPHandle->ThreadID) && (Connection_Table[i].target==HTTPHandle->target) && (Connection_Table[i].port==HTTPHandle->port) )
		{
			if (Connection_Table[i].io==0)
			{
				return(i);
			}
		}
	}
	return(-1); //Connection Not Found
}
/*******************************************************************************************/
//! This function checks the connection table searching for the first unused connection.
/*!
\param HTTPHandle Currently ignored.
\return Returns an index to the CONEXION item in the connection table.
\note This function is only used internally by HTTPCore Module.
\note If no free connection is found, -1 is returned.
*/
/*******************************************************************************************/
static int GetFirstUnUsedConnectionAgainstTarget(PHHANDLE HTTPHandle) 
{
	for(unsigned int i=0;i<MAX_OPEN_CONNECTIONS;i++)
	{
		if ( (Connection_Table[i].target==TARGET_FREE) && (!Connection_Table[i].io) && (!Connection_Table[i].PENDING_PIPELINE_REQUESTS) )
		{
			return(i);
		}
	}
	return(-1);
}
/*******************************************************************************************/
//! This function Adds a pending request struct to the connection pool
/*!
\param connection CONEXION struct returned by a previous call to GetSocketConnection. From this connection the first added request struct will be removed (FIFO)
\return This function returns the number of pending pipelined request. 
*/
/*******************************************************************************************/
int RemovePipeLineRequest(STABLISHED_CONNECTION *connection)
{
	if (connection->PENDING_PIPELINE_REQUESTS) 
	{
		for (int i=0;i<connection->PENDING_PIPELINE_REQUESTS -1;i++)
		{
			connection->PIPELINE_Request[i]=connection->PIPELINE_Request[i +1];
			connection->PIPELINE_Request_ID[i]=connection->PIPELINE_Request_ID[i+1];		
		}
		connection->PENDING_PIPELINE_REQUESTS--;
		connection->PIPELINE_Request=(PHTTP_DATA*)realloc(connection->PIPELINE_Request,sizeof(PHTTP_DATA) * (connection->PENDING_PIPELINE_REQUESTS));
		connection->PIPELINE_Request_ID= (unsigned long *) realloc(connection->PIPELINE_Request_ID,sizeof(unsigned long) * connection->PENDING_PIPELINE_REQUESTS);		
		if (!connection->PENDING_PIPELINE_REQUESTS)
		{
			connection->PIPELINE_Request=NULL;
			connection->PIPELINE_Request_ID = NULL;
			return(0);
		} 
	}
	return(connection->PENDING_PIPELINE_REQUESTS);

}
/*******************************************************************************************/
//! This function is the method for adding a new pending HTTP Request to the connection Pool. This added request will be sent to the server outside this function.
/*!
\param connection CONEXION struct returned by a previous call to GetSocketConnection
\param request Pointer to a request struct generated by SendHTTPRequest()
\return This function returns the ID of the added Pending pipelined request from the server. 
This returned ID value is needed by SendRawHTTPRequest() to known when the new response is ready for reading
*/
/*******************************************************************************************/
static unsigned long AddPipeLineRequest(STABLISHED_CONNECTION *connection, PHTTP_DATA request)
{  
#ifdef _DBG_
	printf("*** AddPipeLineRequest: Añadiendo %i en conexion %i (%i +1)\n",PIPELINE_Request_ID,connection->id,connection->PENDING_PIPELINE_REQUESTS);
#endif
	connection->PIPELINE_Request=(struct _data **)realloc(connection->PIPELINE_Request,sizeof(struct _data *) * (connection->PENDING_PIPELINE_REQUESTS+1));
	connection->PIPELINE_Request[connection->PENDING_PIPELINE_REQUESTS]=request;

	connection->PIPELINE_Request_ID= (unsigned long *) realloc(connection->PIPELINE_Request_ID,sizeof(unsigned long) * (connection->PENDING_PIPELINE_REQUESTS+1));	
	connection->PIPELINE_Request_ID[connection->PENDING_PIPELINE_REQUESTS ]=PIPELINE_Request_ID++;
	connection->PENDING_PIPELINE_REQUESTS++;	
	//UnLockMutex(&connection->lock);
	/* TODO 1 : Revisar de donde sale ese unlockmutex- Es necesario? el acceso esta restringido con el mutex global LOCK */
	return(connection->PIPELINE_Request_ID[connection->PENDING_PIPELINE_REQUESTS -1]);
}


/*******************************************************************************************/
//! This function returns a CONEXION struct with initialized sockets. If the connection was previously initialized that struct will be resused.
/*!
\param HTTPHandle handle to the remote host
\param request To support pipelining, This function adds the request to the connection pool.
\param id pointer to a long that will store the id asigned to the request. Each request have a unique incremental ID.
\return Initilized CONEXION struct against the remote host.
\note This internal function manages the CONEXION sockets and stablish connections when needed .
\note If the remote target cannot be reached or there are no free sockets the function returns null.
*/
/*******************************************************************************************/
static STABLISHED_CONNECTION *GetSocketConnection(PHHANDLE HTTPHandle, PHTTP_DATA request, unsigned long *id)
{
	int FirstEmptySlot=-1;
	int FirstIdleSlot=-1;
	int i=-1;

	STABLISHED_CONNECTION * connection;


	//TODO: Que hacemos con io ?
	/*
	IO tiene sentido para señalar un socket que esta siendo utilizado para establecer la conexion ( connect) y sobre el que no se soportan mas operaciones de pipelining dado que no aun no esta en uso
	Debemos usarlo para evitar la reutilización de ese socket únicamente en ese momento :?

	*/
	LockMutex(&lock);
	connection = HTTPHandle->conexion;



	//Check if the Current handle is binded to a previously stablished connection
	if ( request && (connection) && 	(connection->target==HTTPHandle->target) && (connection->port==HTTPHandle->port) && (connection->ThreadID==HTTPHandle->ThreadID)  )
	{ 
		if  (!HTTPHandle->conexion->io )
		{
#ifdef _DBG_
			printf("[DBG]: Direct Reuse Connection %3.3i- (%3.3i requests against %s)\n",HTTPHandle->conexion->id,HTTPHandle->conexion->NumberOfRequests,HTTPHandle->targetDNS);
#endif
			*id=AddPipeLineRequest(connection,request);
			//UnLockMutex(&lock);
		} else {
			while (!HTTPHandle->conexion->io) {
#ifdef _DBG_
				printf("[DBG]: Thread %i Waiting for io\n",*id);
#endif
				Sleep(500);
			}
			*id=AddPipeLineRequest(connection,request);
		}
		UnLockMutex(&lock);	
		return(connection);
	} 

	//Search For stablished connetions that are not currently used - TODO: Check if this is a good idea, maybe not
	FirstIdleSlot=GetFirstIdleConnectionAgainstTarget(HTTPHandle);
	if (FirstIdleSlot!=-1) //Idle Connection Found. Reuse connection
	{
#ifdef _DBG_
		printf("[DBG]: Reuse Connection %3.3i  - %3.3i requests against %s\n",FirstIdleSlot,Connection_Table[FirstIdleSlot].NumberOfRequests,HTTPHandle->targetDNS);
#endif
		HTTPHandle->conexion=&Connection_Table[FirstIdleSlot];
		*id=AddPipeLineRequest(HTTPHandle->conexion,request);
		UnLockMutex(&lock);
		return(HTTPHandle->conexion);
	}

	/*
	//No Unused Connections against designated target Found. Try to stablish a new connection
	i=GetNumberOfConnectionsAgainstTarget(HTTPHandle);
	if (i>=MAX_OPEN_CONNETIONS_AGAINST_SAME_HOST) //Maximum Connection Limit Reached
	{
	#ifdef _DBG_
	//Unable to stablish another connection against that host. Connection limit reached.
	//Try increasing MAX_OPEN_CONNETIONS_AGAINST_SAME_HOST
	printf("[DBG]: Unable to stablish another connection against that host. Connection limit reached");
	#endif
	UnLockMutex(&lock);
	return(NULL);
	}
	*/

	FirstEmptySlot=GetFirstUnUsedConnectionAgainstTarget(HTTPHandle);
	if (FirstEmptySlot==-1) //Connection table full. Try Again Later
	{
		//Unable to get a free Socket connection against target. Maybe your application is too aggresive. Try increasing MAX_OPEN_CONNECTIONS
#ifdef _DBG_
		printf("[DBG]: Unable to get a free Socket connection against target. Maybe your application is too aggresive");
#endif
		printf("UNABLE TO GET FREE SOCKET!!!\n");		
		UnLockMutex(&lock);
		*id = 0;
		return(NULL);
	}

	Connection_Table[FirstEmptySlot].io=1;
#ifdef _DBG_
	printf("[DBG]: Using free slot %3.3i against %s:%i\n",FirstEmptySlot,HTTPHandle->targetDNS,HTTPHandle->port);
	printf("Target: %i\n",HTTPHandle->target);
#endif
	

	Connection_Table[FirstEmptySlot].target=HTTPHandle->target;
	strcpy(Connection_Table[FirstEmptySlot].targetDNS,HTTPHandle->targetDNS);
	Connection_Table[FirstEmptySlot].port=HTTPHandle->port;
	if (HTTPHandle->ProxyHost)
	{
		Connection_Table[FirstEmptySlot].port=atoi(HTTPHandle->ProxyPort);
		Connection_Table[FirstEmptySlot].ConnectionAgainstProxy=1;
	} else {
		Connection_Table[FirstEmptySlot].ConnectionAgainstProxy=0;
	}
	Connection_Table[FirstEmptySlot].NeedSSL=HTTPHandle->NeedSSL;
	Connection_Table[FirstEmptySlot].BwLimit=HTTPHandle->DownloadBwLimit ? atoi(HTTPHandle->DownloadBwLimit) : NULL;
	Connection_Table[FirstEmptySlot].ThreadID = HTTPHandle->ThreadID;

#ifdef _DBG_
	printf("CONEXION: Socket %i (%s:%i)\n",FirstEmptySlot,inet_ntoa(Connection_Table[FirstEmptySlot].webserver.sin_addr),Connection_Table[FirstEmptySlot].port);
	printf("LLAMANDO A StablishConnection desde el GetSocketConnection\n");
#endif

	UnLockMutex(&lock);

	if (!StablishConnection(&Connection_Table[FirstEmptySlot]))
	{
#ifdef _DBG_
		printf("CONEXION FALLIDA\n");
#endif
		LockMutex(&lock);
		FreeConnection(&Connection_Table[FirstEmptySlot]);
		UnLockMutex(&lock);
		*id = 0;
		return(NULL);
	}
	HTTPHandle->conexion=&Connection_Table[FirstEmptySlot];
	LockMutex(&lock);
	*id=AddPipeLineRequest(&Connection_Table[FirstEmptySlot],request);
	//SendHTTPRequestData(HTTPHandle->conexion, request);
	Connection_Table[FirstEmptySlot].io=0;
	UnLockMutex(&lock);
	return(&Connection_Table[FirstEmptySlot]);//&conexion[FirstEmptySlot]);

}
/*******************************************************************************************/
//   ******************            HTTP CORE FUNCTIONS            **********************
/*******************************************************************************************/

/***************************************************************************************************************/
//! This function gets an stablished connection against the remote host, sends the generated HTTP
//!the request and Waits for a response. Callbacks are called at this point.
/*!    
\param HTTPHandle Handle to the remote host.
\param request struct that stores both header and post data that will be delivered to the remote HTTP Host.
\return: returns a PHTTP_DATA struct however, if the remote host can not be reached, NULL is returned instead.
\note If the remote host does not return data, and empty struct is returned.
\note This function shouldnt be called remotely as for example, does not suport authentication. 
Instead, use SendHTTPRequest() exported at the public interface.
\note Registered CallBacks are called from this point.    
*/
/***************************************************************************************************************/
PHTTP_DATA DispatchHTTPRequest(PHHANDLE HTTPHandle,PHTTP_DATA request)
{

	PHTTP_DATA response = NULL;
	STABLISHED_CONNECTION *conexion;
	unsigned long ret;
	unsigned long RequestID;

	if (request)
	{
		//ret = DoCallBack((!HTTPHandle->ProxyHost) ?  CBTYPE_CLIENT_REQUEST : CBTYPE_PROXY_REQUEST ,HTTPHandle,request,NULL);
		ret = DoCallBack(CBTYPE_CLIENT_REQUEST ,HTTPHandle,&request,&response);

		if (ret & CBRET_STATUS_CANCEL_REQUEST)
		{
			return(response);
		}
		conexion=GetSocketConnection(HTTPHandle,request,&RequestID);
		SendHTTPRequestData(conexion,request);
	} else {
		conexion=GetSocketConnection(HTTPHandle,request,&RequestID);
	}

	if (!conexion) {
		return(NULL);
	}

	while (RequestID != conexion->PIPELINE_Request_ID[0])
	{
#ifdef _DBG_
		printf("Waiting for ReadHTTPResponseData() %d / %d\n",RequestID,conexion->PIPELINE_Request_ID[0]);
#endif
		Sleep(100);
	}
#ifdef _DBG_
	printf("LECTURA: LEYENDO PETICION %i en conexion %i\n",RequestID,conexion->id);
#endif

	response = ReadHTTPResponseData(conexion,request,&lock);

	ret = DoCallBack((!HTTPHandle->ProxyHost) ?  CBTYPE_CLIENT_RESPONSE : CBTYPE_PROXY_RESPONSE,HTTPHandle,&request,&response);

	if (ret & CBRET_STATUS_CANCEL_REQUEST)
	{
		FreeHTTPData(response);
		return(NULL);
	}
	return(response);
}


/***************************************************************************************************************/

//! This function is used to start the HTTP Core Engine and must be called only once.
/*!
\note this function is exported but must be called only from HTTP.cpp and must not be called manually.
\note Under Win32, WSA Sockets are also initialized.
\note Supported Core Callbacks must be registered here. Example Chunk encoding, gzip compression..
*/

/***************************************************************************************************************/

int InitHTTPApiCore(void)
{
	unsigned int  i;
#ifdef __WIN32__RELEASE__
	DWORD dwThread;
	WSADATA ws;
#endif

	if (!Connection_Table)
	{
#ifdef __WIN32__RELEASE__
		if (WSAStartup( MAKEWORD(2,2), &ws )!=0) {
			return(0);
		}
#endif
		Connection_Table=(STABLISHED_CONNECTION*)malloc(sizeof(STABLISHED_CONNECTION) * MAX_OPEN_CONNECTIONS);

		for(i=0;i<MAX_OPEN_CONNECTIONS;i++) {
			memset(&Connection_Table[i],'\0',sizeof(STABLISHED_CONNECTION));
			InitMutex(&Connection_Table[i].lock);
			Connection_Table[i].target=TARGET_FREE;
			Connection_Table[i].id=i;
		}

		InitMutex(&lock);
#ifdef __WIN32__RELEASE__
		FreeConnectionHandle=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE) CleanConnectionTable, (LPVOID) i, 0, &dwThread);
#else
		//pthread_create(&e_th, NULL, CleanConnectionTable, (void *)i);
		pthread_create(&FreeConnectionHandle, NULL, CleanConnectionTable, (void *)i);
#endif

		//Load Defined CallBacks..
		RegisterHTTPCallBack( CBTYPE_CLIENT_RESPONSE | CBTYPE_PROXY_RESPONSE, (HTTP_IO_REQUEST_CALLBACK)CBDecodeChunk );
#ifdef _ZLIB_SUPPORT_
		RegisterHTTPCallBack( CBTYPE_CLIENT_REQUEST | CBTYPE_CLIENT_RESPONSE , (HTTP_IO_REQUEST_CALLBACK)CBDeflate );
#endif

#ifdef _OPENSSL_SUPPORT_
		SSL_load_error_strings();
		SSL_library_init();
#endif

		/*Pipelining.. */
		PIPELINE_Request_ID = 0;

		/* IO FILEMAPPING */
		InitFileMapping();
		return(1);
	}

	return(2); //#define ERROR_ENGINE_ALREADY_INITIALIZED 2

}
/***************************************************************************************************************/

//! This function stops the HTTP Core Engine.
/*!
\note this function is exported but must be called only from the HTTP.cpp and must not be called manually.
\note As CallBacks table will be erased (This also include user registered callbacks)
*/
/***************************************************************************************************************/
void CloseHTTPApiCore(void) {


	LockMutex(&lock);
#ifdef __WIN32__RELEASE__
	unsigned int dwExitCode=0;
	TerminateThread(FreeConnectionHandle,dwExitCode);
	CloseHandle(FreeConnectionHandle);
	WSACleanup();
#else
	pthread_cancel(FreeConnectionHandle);
#endif
	for(unsigned int i=0;i<MAX_OPEN_CONNECTIONS;i++) {
		LockMutex(&Connection_Table[i].lock);
		shutdown(Connection_Table[i].datasock,2);
		if (Connection_Table[i].target!=TARGET_FREE) {
			shutdown(Connection_Table[i].datasock,2);
			closesocket(Connection_Table[i].datasock);
		}
		Connection_Table[i].target=0;
		UnLockMutex(&Connection_Table[i].lock);
		DeleteMutex(&Connection_Table[i].lock);
		memset(&Connection_Table[i],0,sizeof(STABLISHED_CONNECTION));

	}
	free(Connection_Table);
	Connection_Table=NULL;

	EndFileMapping();


	UnLockMutex(&lock);
	DeleteMutex(&lock);
	RemoveHTTPCallBack(CBTYPE_CALLBACK_ALL,NULL);
}

/******************************************************************************/
//! This function Initializes an HTTP_DATA struct with the headers and and data sent or returned by a client or an http server.
/*!
\param header pointer to an string that contains HTTP headers. This value can be null
\param postdata pointer to an string that contains HTTP data. This value can be null.
\return pointer to an initialized HTTP_DATA struct.
\note if header or postdata is null and empy string will be allocated.
*/
/*******************************************************************************/
PHTTP_DATA InitHTTPData(char *header, char *postdata)
{
	PHTTP_DATA data=(PHTTP_DATA)malloc(sizeof(HTTP_DATA));
	if (header)
	{
		data->Header=_strdup(header);
		data->HeaderSize= (unsigned int) strlen(header);
	} else
	{
		data->Header=_strdup("");
		data->HeaderSize=0;
	}
	if (postdata)
	{
		data->Data=_strdup(postdata);
		data->DataSize=(unsigned int) strlen(postdata);
	} else
	{
		data->Data=_strdup("");
		data->DataSize=0;
	}
	return(data);
}
/*******************************************************************************/
//! This function deallocates the memory of an an HTTP_DATA struct.
/*!
\param data pointer to an HTTP_DATA struct allocated by a previous call to InitHTTPData().
\note This function also tries to match if the assigned memory to HTTP_DATA->Data is a memory mapping. If so, the file mapping will be removed
*/
/******************************************************************************/
void FreeHTTPData(HTTP_DATA *data)
{
	if (data)
	{
		if (data->Data) data->Data=DeleteFileMapping(data->Data);
		if (data->Data) free(data->Data);
		if (data->Header) free(data->Header);
		free(data);
	}
}

