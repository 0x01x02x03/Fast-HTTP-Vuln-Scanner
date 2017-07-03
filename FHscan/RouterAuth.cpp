/*
*  Fast HTTP AUTH SCANNER - v0.8
*
*  Router Auth Scanner Module: Scans for known authentication path
*
*/

//TODO: Anadir retries
//TODO: Soltar mensajes de debug...
//TODO: Postdata deberia ser un puntero, que valga NULL si no hay datos..
//TODO: Anadir Location
/*
#include <stdio.h>
#ifdef __WIN32__RELEASE__
#include <windows.h>
#endif*/
#ifdef OLD_RELEASE
#include "HTTPCore/HTTP.h"
#else
#include "../HTTPCore/HTTP.h"
#endif
#include "estructuras.h"
#include "FHScan.h"


#include "Reporting/LogSettings.h"

extern int bruteforce;
#define MAX_TIMEOUT_RETRY 5 //Due to host timeout we will retry not more than 5 connections

PREQUEST DuplicateData(struct _request *data)
{
	struct _request *new_data=(struct _request*)malloc(sizeof(struct _request));
	memset(new_data,'\0',sizeof(struct _request));

	new_data->ip=data->ip;
	strncpy(new_data->hostname,data->hostname,sizeof(new_data->hostname)-1);
	new_data->port=data->port;
	new_data->NeedSSL=data->NeedSSL;

	new_data->request=(PHTTP_DATA)malloc(sizeof(HTTP_DATA));
	new_data->response=(PHTTP_DATA)malloc(sizeof(HTTP_DATA));
	new_data->request->Data=_strdup(data->request->Data);
	new_data->request->Header=_strdup(data->request->Header);
	new_data->request->DataSize=data->request->DataSize;
	new_data->request->HeaderSize=data->request->HeaderSize;

	new_data->response->Data=_strdup(data->response->Data);
	new_data->response->Header=_strdup(data->response->Header);
	new_data->response->DataSize=data->response->DataSize;
	new_data->response->HeaderSize=data->response->HeaderSize;

	strcpy(new_data->url,data->url);
	new_data->server=_strdup(data->server);
	new_data->status=data->status;
	new_data->challenge=data->challenge;

	return(new_data);
}

/*******************************************************************************/
static int ValidHTTPResponse(PREQUEST data)
{
	return ( (data) && (data->response->Header) && (data->status>100) && (data->status<520) );
}
/******************************************************************************/
static struct _request *CheckRedirect(HTTPHANDLE HTTPHandle, struct _request *data)
{
	char path[10000];
	int iport;
	int port;
	char host[10000];
	int ssl=0;

	if (data->status != HTTP_STATUS_DENIED)
	{
		char *NewLocation=GetHeaderValue(data->response->Header, "Location:",0);
		if ( (NewLocation) && (strlen(NewLocation)>0) )
		{
#ifdef _DBG_
			printf("****** Encontrada redireccion a : %s\n",NewLocation);
#endif
			//HTTP Request
			if ( strnicmp( NewLocation, "http://", 7 ) == 0 )
		 {
			 memcpy( NewLocation, "http", 4 );
			 if     ( sscanf( NewLocation, "http://%[^:/]:%i%s", host, &iport, path ) == 3 )   // http://host:80/url
				 port = (unsigned short) iport;
			 else if ( sscanf( NewLocation, "http://%[^/]%s", host, path ) == 2 ) //  http://host/url
				 port = 80;
			 else if ( sscanf( NewLocation, "http://%[^:/]:%i", host, &iport ) == 2 ) //  http://host:port
			 {
				 port = (unsigned short) iport;
				 *path = '\0';
			 }
			 else if ( sscanf( NewLocation, "http://%[^/]", host ) == 1 )
			 {
				 port = 80;
				 *path = '\0';
			 } else {
#ifdef _DBG_
				 printf("Unable to parse HTTP location...\n");
#endif
				 free(NewLocation);
				 return(NULL);
			 }
		 }
			//HTTPS Request
			else if ( strnicmp( NewLocation, "https://", 8 ) == 0 )
		 {
			 ssl=1;
			 memcpy( NewLocation, "https", 5 );
			 if     ( sscanf( NewLocation, "https://%[^:/]:%d%s", host, &iport, path ) == 3 )   // http://host:80/url
				 port = (unsigned short) iport;
			 else if ( sscanf( NewLocation, "https://%[^/]%s", host, path ) == 2 ) //  http://host/url
				 port = 443;
			 else if ( sscanf( NewLocation, "https://%[^:/]:%d", host, &iport ) == 2 ) //  http://host:port
			 {
				 port = (unsigned short) iport;
				 *path = '\0';
			 }
			 else if ( sscanf( NewLocation, "https://%[^/]", host ) == 1 )
			 {
				 port = 443;
				 *path = '\0';
			 } else {
#ifdef _DBG_
				 printf("Unable to parse HTTPS location...\n");
#endif
				 free(NewLocation);
				 return(NULL);
			 }
			} else {

				port=data->port;
				ssl=data->NeedSSL;
				strncpy(host,data->hostname,sizeof(host)-1);
				if (NewLocation[0]=='/')
				{
					strncpy(path,NewLocation,sizeof(path)-1);
				} else {
					snprintf(path,sizeof(path)-1,"/%s",NewLocation);
				}

		 }
			free(NewLocation);
			if (*path=='\0') strcpy(path,"/");

#ifdef _DBG_
			printf("CheckRedirect:RedirectHost: %s\n",host);
			printf("CheckRedirect:Redirecturl %s\n",path);
			printf("CheckRedirect:RedirectPort %i \n",port);
#endif
			//TODO: Cambiar puerto y SSL si es necesario...
			struct _request *tmp=DuplicateData(data);
			tmp->NeedSSL=ssl;
			tmp->port=port;
			struct _request *new_response=SendHttpRequest( HTTPHandle,NULL,"GET",path,NULL,NULL,NULL,NO_AUTH);
			FreeRequest(tmp);
			if (new_response)
			{
				if (!ValidHTTPResponse(new_response))  { FreeRequest(new_response); return(NULL); }
#ifdef _DBG_
				printf("CheckRedirect:Redirectstatus %i \n",new_response->status);
#endif
				strncpy(new_response->url,path,sizeof(new_response->url)-1);
				return(new_response);
			}
		}
	}
	return(NULL);
}
/*******************************************************************************/
#define PASSWORD_NOT_FOUND -1
static int BruteforceAuth( HTTPHANDLE HTTPHandle,struct _request *data,struct _fakeauth *AuthData,int nUsers, USERLIST *userpass,int challenge) {

	struct _request *new_response;
	int CookieNeeded=0;
    char *lpcookie=NULL;
    char cookie[256]="";
	int retries=MAX_TIMEOUT_RETRY;

    if (!bruteforce)  return(PASSWORD_NOT_FOUND);

	if (strstr(AuthData->postdata,"Cookie")!=NULL) {
		CookieNeeded=1;
        if (strstr(AuthData->postdata,"Cookie: !!!UPDATECOOKIE!!!")!=NULL) {
            CookieNeeded=2;
            lpcookie=GetHeaderValue(data->response->Header,"Set-Cookie: ",0);
            if (lpcookie) {
				snprintf(cookie,sizeof(cookie)-1,"Cookie: %s",lpcookie);
            }  else CookieNeeded=0;
        }
	}



    for(int k=0;k<nUsers;k++)
    {
		//
#ifdef _DBG_
		printf("!!!Enviando login/password (%i/%i): %s - %s (authmethod %i )\n",k,nUsers,userpass[k].UserName,userpass[k].Password,challenge);
#endif

		do {
			SetHTTPConfig(HTTPHandle,OPT_HTTP_COOKIE,NULL);
            switch (CookieNeeded) {
                case 0:
					new_response=SendHttpRequest( HTTPHandle,NULL,AuthData->method,AuthData->authurl,AuthData->postdata,userpass[k].UserName,userpass[k].Password,challenge);
                    break;
				case 1:
					SetHTTPConfig(HTTPHandle,OPT_HTTP_COOKIE,AuthData->postdata);
					new_response=SendHttpRequest( HTTPHandle,NULL,AuthData->method,AuthData->authurl,NULL,userpass[k].UserName,userpass[k].Password,challenge);
                    break;
                case 2:
					if (lpcookie) {
						SetHTTPConfig(HTTPHandle,OPT_HTTP_COOKIE,cookie);
						new_response=SendHttpRequest( HTTPHandle,NULL,AuthData->method,AuthData->authurl,NULL,userpass[k].UserName,userpass[k].Password,challenge);
						free(lpcookie); lpcookie=NULL;
					} else {
						new_response=SendHttpRequest( HTTPHandle,NULL,AuthData->method,AuthData->authurl,NULL,userpass[k].UserName,userpass[k].Password,challenge);
                    }
                    break;
            }

			if (!ValidHTTPResponse(new_response)) {new_response=(PREQUEST)FreeRequest(new_response); }
			if (!new_response) {
				retries--;
				Sleep(500);
			}
		}while ( (!new_response) && (retries>0)  && (strlen(userpass[k].UserName)>0) && (strlen(userpass[k].Password)>0));


		/* Clean Cookie status */
		SetHTTPConfig(HTTPHandle,OPT_HTTP_COOKIE,NULL);
		if (new_response)
		{
#ifdef _DBG_
			printf("ESTADO: %i\n",new_response->status);
#endif

			if (new_response->status <= HTTP_STATUS_REDIRECT ) //302
			{
				if (new_response->status == HTTP_STATUS_REDIRECT )
				{

					char *p = GetHeaderValue(new_response->response->Header,"Location",0);
					if (p)
					{
						if (stricmp(p,AuthData->authurl)==0 )
						{
							/*TODO: Realizar de nuevo la peticion y ver si requiere auth */
							new_response->status=401;
							UpdateHTMLReport(new_response,MESSAGE_ROUTER_PASSFOUND,userpass[k].UserName,userpass[k].Password,new_response->url,NULL);
							FreeRequest(new_response);
							return(k);
						}
						free(p);
					}
				} else {
					new_response->status=401;
					UpdateHTMLReport(new_response,MESSAGE_ROUTER_PASSFOUND,userpass[k].UserName,userpass[k].Password,new_response->url,NULL);
					FreeRequest(new_response);
					return(k);
				}
			}
			if (CookieNeeded==2)
			{
                lpcookie=GetHeaderValue(data->response->Header,"Set-Cookie: ",0);
				if (lpcookie) {
                    snprintf(cookie,sizeof(cookie)-1,"Cookie: %s",lpcookie);
                }
            }
			FreeRequest(new_response);
		}
	}
	return(PASSWORD_NOT_FOUND);
}
/*******************************************************************************/
struct _request *CheckRouterAuth(HTTPHANDLE HTTPHandle,struct _request *data,int nRouterAuth, struct _fakeauth *AuthData,int nUsers, USERLIST *userpass)
{
	struct _request *response;//=NULL;
	int ret;
	char *lpcookie=NULL;

/*
 * Revisamos si el dispositivo requiere autenticacion en la pagina principal o en alguna de las que aparecen en el campo Location
 */
	if (data->status!=HTTP_STATUS_DENIED) {
		response=CheckRedirect(HTTPHandle,data);
		if (response)
		{
			if ( (response->status == HTTP_STATUS_DENIED) && (response->challenge!=NO_AUTH))
			{
				struct _fakeauth RedirectAuth;
				memset(&RedirectAuth,'\0',sizeof(struct _fakeauth));
				strncpy(RedirectAuth.authurl,response->url,sizeof(RedirectAuth.authurl)-1);
				strcpy(RedirectAuth.method,"GET");
				ret=BruteforceAuth( HTTPHandle,response,&RedirectAuth, nUsers, userpass,response->challenge);
				if (ret!=PASSWORD_NOT_FOUND)
				{
				//	UpdateHTMLReport(response,MESSAGE_ROUTER_PASSFOUND,userpass[ret].UserName,userpass[ret].Password,response->url,NULL);

				} else {
					UpdateHTMLReport(response,MESSAGE_WEBFORMS_PASSNOTFOUND,"UNKNOWN","UNKNOWN",response->url,NULL);
				}
				return(response);
			}
			response=(PREQUEST)FreeRequest(response);
		}
	}



	for(int i=0;i<nRouterAuth;i++)
	{
		//	   printf("Verificando %i - %s\n",i,AuthData[i].authurl);
		if ( (AuthData[i].status == data->status ) &&
			( (strncmp(data->server,AuthData[i].server,strlen(AuthData[i].server))==0) ||
			(AuthData[i].server[0]=='*') ||
			( (strlen(data->server)==0) && (strcmp(AuthData[i].server," ")==0)) )
			)
		{

#ifdef _DBG_
			printf("Verificando %i - %s\n",i,AuthData[i].authurl);
			printf("------------enviando---------------\n");
#endif
			if (i==0) {
				//			 printf("aki..........\n");
				response=DuplicateData(data);
			} else {
				int CookieNeeded=0;
				if (strstr(AuthData[i].postdata,"Cookie")!=NULL)
				{
					CookieNeeded=1;

					if (strstr(AuthData[i].postdata,"Cookie: !!!UPDATECOOKIE!!!")!=NULL)
					{
						char tmp[256];
						lpcookie=GetHeaderValue(data->response->Header,"Set-Cookie: ",0);
						if (lpcookie) {
							snprintf(tmp,sizeof(tmp)-1,"Cookie: %s",lpcookie);
							free(lpcookie);
							lpcookie=_strdup(tmp);
						} else CookieNeeded=0;
					} else{
						lpcookie=_strdup(AuthData[i].postdata);
					}
				}

				//  response=SendHttpRequest( data,AuthData[i].method,AuthData[i].authurl,AuthData[i].postdata,(char*)VERSION,NULL,NULL,NULL,NO_AUTH);
					if (CookieNeeded) {
						SetHTTPConfig(HTTPHandle,OPT_HTTP_COOKIE,lpcookie);//AuthData[i].postdata);
						response=SendHttpRequest( HTTPHandle,NULL,AuthData[i].method,AuthData[i].authurl,NULL,NULL,NULL,NO_AUTH);
						SetHTTPConfig(HTTPHandle,OPT_HTTP_COOKIE,NULL);
						free(lpcookie);
					} else {
						response=SendHttpRequest( HTTPHandle,NULL,AuthData[i].method,AuthData[i].authurl,AuthData[i].postdata,NULL,NULL,NO_AUTH);
					}
				}
				//SetHTTPConfig(HTTPHandle,OPT_HTTP_COOKIE,NULL);
			//

			if (!ValidHTTPResponse(response)) { response=(PREQUEST)FreeRequest(response); }
		if (response)
		 {
#ifdef _DBG_
			 printf("code: %i buffer: %s\n",response->status,response->response->Data);
			 printf("/Headers: %s\n",response->response->Header);
			 //for(int j=0;j<response->nheaders;j++) printf("header: %s\n",response->header[j]);
#endif

			 if ( (response->status == HTTP_STATUS_DENIED) && (response->challenge!=NO_AUTH))
			 {
				 //ret=BruteforceAuth( HTTPHandle,data,&AuthData[i], nUsers, userpass,response->challenge);
				 ret=BruteforceAuth( HTTPHandle,response,&AuthData[i], nUsers, userpass,response->challenge);
				 if (ret!=PASSWORD_NOT_FOUND)
				 {
					 //UpdateHTMLReport(response,MESSAGE_ROUTER_PASSFOUND,userpass[ret].UserName,userpass[ret].Password,AuthData[i].authurl,NULL);

				 } else {
					 UpdateHTMLReport(response,MESSAGE_WEBFORMS_PASSNOTFOUND,"UNKNOWN","UNKNOWN",AuthData[i].authurl,NULL);
				 }
				 return(response);
			 }
			 response=(PREQUEST)FreeRequest(response);
			}
		}
	}
	return(NULL);
}

//---------------------------------------------------------------------------------

