/*
//TODO:

- soporte de plugins (de autenticacion escaneo )
- Anadir firmas: http://1105/admin/webset.html?autoref=0&weblang=0

* permitir enviar la pagina autenticada a updatehtmlreport() en vez de la pagina antigua.
*/
#include "FHScan.h"
#include "config.h"
#include "time.h"
#include "webservers.h"
#include "RouterAuth.h"
#include "webforms.h"
#include "Reporting/LogSettings.h"


CRITICAL_SECTION CSip;
CRITICAL_SECTION CSThreads;

unsigned int    nthreads=9;
USERLIST        *userpass=NULL;
int             nUsers=0;
USERLOGIN	    *logins;
int             nLogins=0;
struct          _fakeauth FakeAuth[MAX_AUTH_LIST];
struct          _ports ports[MAX_PORTS];
FILE            *ipfile=NULL;
int             FullUserList=0;
int             ShowAllhosts=0;
int             bruteforce=1;  //Yeah! try to discover default passwords
int 			VulnChecks=1;
int             nports=0;
int             nRouterAuth=0;
int				csv = 0;
int             ThreadsActivos=0;
extern int nvlist;
extern VLIST    vlist[200];
int     nKnownWebservers;
char    **KnownWebservers;
char	**KnownRouters;
int		nKnownRouters;

unsigned long currentip=0,endip=0;
char *vhost=NULL;
char *ipfilepath=NULL;

int TotalRequests=0;
int nRequests=0;


FILE *dump = NULL;


/******************************************************************************/

int GetNumberOfRequests(void) {
int i=0;
if (ipfile) {
	char line[512];
	while(!feof(ipfile)) {
		if ( ReadAndSanitizeInput(ipfile,line,sizeof(line)) ){
			i++;
		}
	}
	fseek(ipfile,0,SEEK_SET );

} else {
	i = endip - currentip;
}
	return(i * nports + nthreads);
}
/******************************************************************************/
/******************************************************************************/

int IsKnownWebServer(char *server, int nKnownWebservers, char **KnownWebservers) {
   if (server)
   {
    for (int i=0;i<nKnownWebservers;i++)
    {
	  if (strnicmp(server,KnownWebservers[i],strlen(KnownWebservers[i]))==0)
      {
         return(1);
      }
    }
   }
   return(0);
}
/*******************************************************************************/
/*******************************************************************************/
int IsKnownRouter(char *server, int nKnownRouters, char **KnownRouters) {
   if (server)
   {
	for (int i=0;i<nKnownRouters;i++)
	{
	  if (strnicmp(server,KnownRouters[i],strlen(KnownRouters[i]))==0)
	  {
		 return(1);
	  }
	}
   }
   return(0);
}
/*******************************************************************************/
/*******************************************************************************/
static long GetNextTarget(char *hostname, int dstSize)
{

	int ret=0;
	LockMutex(&CSip);


	if (ipfile) {
		if (!feof(ipfile))
		{
			char line[512];
			memset(line,'\0',sizeof(line));
			if ( ReadAndSanitizeInput(ipfile,line,sizeof(line)) )
			{
				strncpy(hostname,line,dstSize-1);
				ret=1;
			}
		}  else {
         	fclose(ipfile);
		}
	} else {
		if (currentip<endip)
		{
			struct sockaddr_in ip;
			ip.sin_addr.s_addr = htonl((long)currentip++);
			strcpy(hostname,inet_ntoa(ip.sin_addr));
			ret=1;
		}
	}
	UnLockMutex(&CSip);
	return(ret);

}
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
//! This function Validates if the remote server returned a valid HTTP Response by locking to the headers and HTTP status code.
/*!
	\param data Pointer to a request struct.
*/
/*******************************************************************************/
static int ValidHTTPResponse(PREQUEST data)
{
	return ( (data) && (data->response->Header) && (data->status>100) && (data->status<520) );
}
/*******************************************************************************/
void *ScanHosts(void *thread) {
	struct _request *data;
	HTTPHANDLE HTTPHandle;//data;
	int ret;
	char hostname[512];


	while ( GetNextTarget(hostname, sizeof(hostname)) )
	{

		for (int i=0;i<nports;i++)
		{
			if (!csv) printf("checking %15s:%5.5i\r",hostname,ports[i].port);

			LockMutex(&CSip);
			nRequests++;

			UnLockMutex(&CSip);

			HTTPHandle=InitHTTPConnectionHandle(hostname,ports[i].port, ports[i].ssl);
			if (HTTPHandle)
			{

				data=SendHttpRequest(HTTPHandle,NULL,"GET","/",NULL,NULL,NULL,NO_AUTH);


				if ( (data) && ( (!ValidHTTPResponse(data)) ||
					( (data->status==400)  && (data->server)  && (strcmp(data->server,"micro_httpd")==0 ) ) )
					) //Hack to detect micro_http devices that returns "400 Bad Request"
				{

					if (ShowAllhosts)
					{
						data=(PREQUEST)FreeRequest(data);
						data=SendHttpRequest(HTTPHandle,NULL,"GET","//",NULL,NULL,NULL,NO_AUTH);
						if (data){
							if (ValidHTTPResponse(data))
							{
								UpdateHTMLReport(data,MESSAGE_FINGERPRINT,NULL,NULL,NULL,NULL);
							}
							data=(PREQUEST)FreeRequest(data);
						}
					}				
					data=(PREQUEST)FreeRequest(data);
				}
				
				if (data)
				{
					char tmp[256];
					sprintf(tmp,"%s\n",hostname);
					fwrite(tmp,1,strlen(tmp),dump);
					if (VulnChecks) {

						char *p=GetHeaderValue(data->response->Header,"Server:",0);
						if (!p) {
							struct _request *head=SendHttpRequest(HTTPHandle,NULL,"HEAD","/",NULL,NULL,NULL,NO_AUTH);							
							if (head){
								if (head->server)  {

									if (data->server) free (data->server);
									data->server=_strdup(head->server);
								}
								FreeRequest(head);
							}
						} else {
							free(p);
						}

						
						UpdateHTMLReport(data,MESSAGE_FINGERPRINT,NULL,NULL,NULL,NULL);
						if ( IsKnownWebServer(data->server,nKnownWebservers,KnownWebservers)  && (!IsKnownRouter(data->server,nKnownRouters,KnownRouters)) ) {
							UpdateHTMLReport(data,MESSAGE_WEBSERVER_FOUND,NULL,NULL,NULL,NULL);
							ret = CheckWebformAuth(HTTPHandle,data,0);
							if (ret==0) CheckVulnerabilities(HTTPHandle,data,nUsers,userpass);

						} else { //El servidor Web es desconocido.. Quizas sea un router
							struct _request *auth=CheckRouterAuth(HTTPHandle,data,nRouterAuth, FakeAuth, nUsers, userpass);
							if (auth==NULL) {
								ret=CheckWebformAuth(HTTPHandle,data,0);
								switch (ret) 
								{
									case -1: //password not found
										UpdateHTMLReport(data,MESSAGE_ROUTER_FOUND,NULL,NULL,NULL,NULL);
										break;
									case 0: //http router authentication schema not found
										if (!IsKnownRouter(data->server,nKnownRouters,KnownRouters))  
										{
											UpdateHTMLReport(data,MESSAGE_WEBSERVER_FOUND,NULL,NULL,NULL,NULL);
											CheckVulnerabilities(HTTPHandle,data,nUsers,userpass);
										} else {
											UpdateHTMLReport(data,MESSAGE_ROUTER_FOUND,NULL,NULL,NULL,NULL);
											UpdateHTMLReport(data,MESSAGE_ROUTER_NOPASSWORD,NULL,NULL,NULL,NULL);
										}
										break;
									case 1: //password found
										UpdateHTMLReport(data,MESSAGE_ROUTER_FOUND,NULL,NULL,NULL,NULL);
										break;

								}
								/*
								if  (ret==-1) {
									if (!IsKnownRouter(data->server,nKnownRouters,KnownRouters))  {
										UpdateHTMLReport(data,MESSAGE_WEBSERVER_FOUND,NULL,NULL,NULL,NULL);
										CheckVulnerabilities(HTTPHandle,data,nUsers,userpass);
									} else {
										UpdateHTMLReport(data,MESSAGE_ROUTER_FOUND,NULL,NULL,NULL,NULL);
										UpdateHTMLReport(data,MESSAGE_ROUTER_NOPASSWORD,NULL,NULL,NULL,NULL);
									}
								}*/
							} else {
								UpdateHTMLReport(data,MESSAGE_ROUTER_FOUND,NULL,NULL,NULL,NULL);
								FreeRequest(auth);
							}
						}
					}
					FreeRequest(data);

				}
				CloseHTTPConnectionHandle(HTTPHandle);
			}

		}
	}
	LockMutex(&CSThreads);
	ThreadsActivos--;
	nRequests++;

	UnLockMutex(&CSThreads);
#ifndef __WIN32__RELEASE__
	pthread_exit(NULL);
#endif
	return NULL;

}

/*******************************************************************************/

int main(int argc, char *argv[]){


	#ifdef __WIN32__RELEASE__
	HANDLE *thread;
	#else
	pthread_t e_th;
	#endif
	int ret;



	InitHTTPApi();
	ret = LoadConfigurationFiles( argc,argv);
	if (ret ==1) {
		CloseHTTPApi();
		return(0);
	}
	if (!csv) {
		printf(" HTTP vulnerability Scanner v1.1\n");
		printf("(c) Andres Tarasco - http://www.tarasco.org\n\n");
	}


	if ( ((endip - currentip ) < nthreads ) && (!ipfile) ) {
		nthreads = endip-currentip;
	}
	if (nthreads>MAXIMUM_WAIT_OBJECTS) {
		nthreads=MAXIMUM_WAIT_OBJECTS;
	}
	InitMutex(&CSip);
	InitMutex(&CSThreads);
	#ifdef __WIN32__RELEASE__
	thread=(HANDLE*)malloc(sizeof(HANDLE)*nthreads);
	#endif


	InitHTMLReport(ipfilepath,currentip,endip,nports,ports,nthreads,1,FullUserList,1);
	dump = fopen("ScannerIPS.log","a+");

	if (!csv) ("Option  Server         status Port password      Path Description/banner\n");


	for(unsigned int i=0;i<nthreads;i++) {
		#ifdef __WIN32__RELEASE__
		thread[i]=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE) ScanHosts, (LPVOID) &i, 0, NULL);
		Sleep(50);
		#else
		LockMutex(&CSThreads);
		ThreadsActivos++;
		UnLockMutex(&CSThreads);
		pthread_create(&e_th, NULL, ScanHosts, (void *)i);
		#endif
	}

	#ifdef __WIN32__RELEASE__
	WaitForMultipleObjects(nthreads,thread,TRUE,INFINITE);
	#else
	while (ThreadsActivos>0) {   Sleep(500);  }
	#endif


	#ifdef __WIN32__RELEASE__
	for(unsigned int i=0;i<nthreads;i++) {

		CloseHandle(thread[i]);
	}
#endif


	CloseHTTPApi();

//	if (LogFile) fclose(LogFile);
	if (!csv)	{
		printf("scan Finished\t\t\t\t\t\n");fflush(stdout);
	} else fflush(stderr);

	CloseHTMLReport();
	DeleteMutex(&CSip);
	DeleteMutex(&CSThreads);


	#ifdef __WIN32__RELEASE__
	free(thread);
	#endif

	for(int i=0;i< nKnownRouters;i++) free(KnownRouters[i]);
	free(KnownRouters);

	for(int i=0;i< nKnownWebservers;i++) free(KnownWebservers[i]);
	free(KnownWebservers);
	for(int i=0;i<nvlist;i++) {
		free(vlist[i].Match);
	}

	free(logins);
	free(userpass);




	if (dump) {
        fclose(dump);
	}

	return(1);

}




