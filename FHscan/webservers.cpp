//TODO: verificar codigo 302 como respuesta valida
//TODO: Verificar proxy_AUTH_REQUIRED para bruteforce :?
//TODO: definir vlist como VLIST *
//TODO: Migrar mensajes a un modulo externo.
//revisar porque se hacen varias peticiones al modulo 200 OK - GET /Fast-HTTP-Auth-Scanner-200-test/ HTTP/1.1

//SI la url principal "/" requiere auth 401 y todas las paginas requieren auth 401 revisar porque no se realiza autenticacion (por ejemplo NTLM)

#ifdef OLD_RELEASE
#include "HTTPCore/HTTP.h"
#include "HTTPCore/HTTPCore.h"
#else
#include "../HTTPCore/HTTP.h"
#include "../HTTPCore/HTTPCore.h"

#endif
#include "webservers.h"
#include "Reporting/LogSettings.h"

VLIST vlist[200]; //Vulnerability LIST
int nvlist = 0;

PREQUEST DuplicateData(struct _request *data);
/******************************************************************************/
char *Directories[50];
char *Files[50];
char *Extensions[10];
/******************************************************************************/
void BruteForceDirectory(HTTPHANDLE HTTPHandle, char *base) {
	unsigned int i, j;

	char path[512];
	char tmp[512];
	PREQUEST response;

	i = 0;
	while (Directories[i][0]) {
		sprintf(path, "%s%s/", base, Directories[i]);
		//	sprintf(tmp,"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n",path,((PHHANDLE)HTTPHandle->targetDNS,VERSION);
		response = SendRawHttpRequest(HTTPHandle, tmp, NULL);
		if (response) {
			if (response->status == 200) {
				printf("PATH Encontrado: %s\n", path);
				BruteForceDirectory(HTTPHandle, base);
			}
			FreeRequest(response);
		}
		i++;
	}

	i = 0;
	while (Files[i][0]) {
		j = 0;
		while (Extensions[j++][0]) {
			sprintf(path, "%s/%s.%s", base, Files[i], Extensions[j]);
			//		sprintf(tmp,"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n",path,((PHHANDLE)HTTPHandle->targetDNS,VERSION);
			response = SendRawHttpRequest(HTTPHandle, tmp, NULL);
			if (response) {
				if (response->status == 200) {
					printf("FILE Encontrado: %s\n", path);
				}
				FreeRequest(response);
			}
			j++;
		}
		i++;
	}

}
/******************************************************************************/
static int ValidHTTPResponse(PREQUEST data) {
	return ((data) && (data->response->Header) && (data->status > 100)
			&& (data->status < 520));
}
/******************************************************************************/
static BOOL CheckForWrongHTTPStatusCode(HTTPHANDLE HTTPHandle,
		unsigned int status) {
	char tmp[512];
	struct _request *new_response;
	snprintf(tmp, sizeof(tmp) - 1, "/FastHTTPAuthScanner%itest/", status);
	new_response = SendHttpRequest(HTTPHandle, NULL,"GET", tmp, NULL,NULL,
			NULL,NO_AUTH);
	if (new_response) {
#ifdef _DBG_
		printf("la respuesta devuelve un codigo: %i\n",new_response->status);
#endif
		if (!ValidHTTPResponse(new_response)) {
			new_response = (PREQUEST) FreeRequest(new_response);
			return (0);
		}
		if (new_response->status == status) {
			new_response = (PREQUEST) FreeRequest(new_response);
			return (1);
		}
		new_response = (PREQUEST) FreeRequest(new_response);
	}
	return (0);
}

/******************************************************************************/
int CheckVulnerabilities(HTTPHANDLE HTTPHandle, struct _request *data,
		int nUsers, USERLIST *userpass) {

	struct _request *response;
//	struct _request *new_response;
	struct _request *bruteforce;
	unsigned int vulns = 0;
	char tmp[512];
	int i, j, k;
	// int Checked403=0,Ignore403=0;
	int Checked401 = 0, Ignore401 = 0;
	int Checked302 = 0, Ignore302 = 0;
	int Checked301 = 0, Ignore301 = 0;
	int Checked200 = 0, Ignore200 = 0;
	int PasswordLocated = 0;
	FILE *proxy = NULL;

	char *host = "www.fbi.gov";
	int  port  = 80;
	char url[]="/";
	char Match[]="Federal Bureau of Investigation Homepage";
	int ret=0;

	PHHANDLE phandle = (PHHANDLE) HTTPHandle;

	if (!phandle->ProxyHost )
	{
 
		sprintf(tmp,"GET http://%s:%i%s HTTP/1.1\r\nHost: %s\r\n\r\n",host,port,url,host);
		response = SendRawHttpRequest(HTTPHandle,"GET http://www.fbi.gov/ HTTP/1.1\r\nHost: www.fbi.gov\r\n\r\n", NULL);
		if (response) 
		{
			if (strstr(response->response->Data,"Federal Bureau of Investigation Homepage") != NULL) 
			{
				ret=1;
			} else {
				if (response->status==502)
				{
					ret=2;
				} else {
					FreeRequest(response);
				}
			}
		}	
		
		if (!ret) 
		{
			sprintf(tmp,"CONNECT %s:%i HTTP/1.0\r\n\r\n",host,port);
			response = SendRawHttpRequest(HTTPHandle, tmp,NULL);
			if (response) 
			{
				if (response->status==200)
				{
					FreeRequest(response);
					response = SendHttpRequest(HTTPHandle,host,"GET",url,NULL,NULL,NULL,0);
					if (response) 
					{
						if (strstr(response->response->Data,"Federal Bureau of Investigation Homepage") != NULL) 
						{
							ret=3;
						} else {
							FreeRequest(response);
							response = SendRawHttpRequest(HTTPHandle, "CONNECT FHSCAN.nonexistent.asdfg:443 HTTP/1.0",NULL);
							if (response){
								if (response->status==502){
									ret=4;
								} else {
									FreeRequest(response);
									response = SendRawHttpRequest(HTTPHandle, "GET http://127.0.0.1:22/ HTTP/1.0\r\n\r\n",NULL);
									if (response)
									{
										if (strstr(response->response->Data,"OpenSSH")!=NULL) {
											ret=5;
										} else {
											FreeRequest(response);
										}

									}
								}
							}
						}
					}			
				} else {
					FreeRequest(response);
				}
				//We must close the connection 
				CancelHttpRequest(HTTPHandle,HTTP_REQUEST_CURRENT);
			}
		}
		if (ret){
			proxy = fopen("ProxyList.txt", "a+");
			if (proxy) { sprintf(tmp, "%s:%i\n", ((PHHANDLE) HTTPHandle)->targetDNS, ((PHHANDLE) HTTPHandle)->port); fwrite(tmp, 1, strlen(tmp), proxy);fclose(proxy);	} 
		}
		switch (ret){
			case 1:
				strcpy(response->url, "/");
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						"The remote Webserver is acting as an HTTP Proxy Server. A GET request against www.fbi.gov was forwarded.");			
				FreeRequest(response);
				break;
			case 2:
				strcpy(response->url, "/");
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						"The remote Webserver is acting as an HTTP Proxy Server. However the request against www.fbi.gov failed.");			
				FreeRequest(response);
				break;
			case 3:
				strcpy(response->url, "/");
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						"The remote Webserver is acting as an HTTP Proxy Server. A CONNECT + GET request against www.fbi.gov was forwarded.");
				FreeRequest(response);
				break;		
			case 4:
				strcpy(response->url, "/");
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						"The remote Webserver is acting as an HTTP Proxy Server. However the CONNECT method against www.fbi.gov:80 failed (maybe only port 443 is accepted).");
				FreeRequest(response);
				break;
			case 5:
				strcpy(response->url, "/");
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						"The remote Webserver is acting as an HTTP Proxy Server. The request \"GET http://127.0.0.1:22/ HTTP/1.0\" returned the SSH version.");
				FreeRequest(response);
				break;
			default:
				break;
		}
	}
	for (i = 0; i < nvlist; i++) {
		//printf("[%i] comparando: %s! con %s!\n",i,data->server,vlist[i].server);
		if ((strlen(vlist[i].server) == 0) || ((data->server != NULL)
				&& (strnicmp(data->server, vlist[i].server, strlen(
						vlist[i].server)) == 0))) {
			if (strcmp(vlist[i].url, data->url) == 0) {
				response = DuplicateData(data);
			} else {
				response = SendHttpRequest(HTTPHandle, NULL,"GET",
						vlist[i].url, NULL,NULL, NULL,NO_AUTH);
			}
			if ((response) && (!ValidHTTPResponse(response))) {
				response = (PREQUEST) FreeRequest(response);
			}
			if (!response) {
#ifdef _DBG_
				printf("Failed Verificando: %s\n",vlist[i].url);
#endif
			} else {
#ifdef _DBG_
				printf("Verificando: %s (%i)\n",vlist[i].url,response->status);
				printf("Resupuesta (%i bytes): %s\n",response->response->DataSize, response->response->Data);
#endif

				//n1njaaaa checks
				//			if ( (response->status==HTTP_STATUS_FORBIDDEN) && (!Checked403) ) { Checked403=1; Ignore403=CheckForWrongHTTPStatusCode(HTTPHandle,HTTP_STATUS_FORBIDDEN); }
				if ((response->status == HTTP_STATUS_DENIED) && (!Checked401)) {
					Checked401 = 1;
					Ignore401 = CheckForWrongHTTPStatusCode(HTTPHandle,
							HTTP_STATUS_DENIED);
				}
				if ((response->status == HTTP_STATUS_REDIRECT) && (!Checked302)) {
					Checked302 = 1;
					Ignore302 = CheckForWrongHTTPStatusCode(HTTPHandle,
							HTTP_STATUS_REDIRECT);
				}
				if ((response->status == HTTP_STATUS_MOVED) && (!Checked301)) {
					Checked301 = 1;
					Ignore301 = CheckForWrongHTTPStatusCode(HTTPHandle,
							HTTP_STATUS_MOVED);
				}
				if ((response->status == HTTP_STATUS_OK) && (!Checked200)) {
					Checked200 = 1;
					Ignore200 = CheckForWrongHTTPStatusCode(HTTPHandle,
							HTTP_STATUS_OK);
				}

				if ((response->response->Data) && (strstr(
						response->response->Data, "<h1>Index of") != NULL)) {
					UpdateHTMLReport(response,
							MESSAGE_WEBSERVER_VULNERABILITY,NULL,
							NULL,vlist[i].url, "(Directory Listing)");
				}

				switch (response->status) {
				//code 5xx
				case HTTP_STATUS_SERVER_ERROR:
				case HTTP_STATUS_NOT_SUPPORTED:
				case HTTP_STATUS_BAD_GATEWAY:
				case HTTP_STATUS_SERVICE_UNAVAIL:
				case HTTP_STATUS_GATEWAY_TIMEOUT:
				case HTTP_STATUS_VERSION_NOT_SUP:
					//code 4xx
				case HTTP_STATUS_UNSUPPORTED_MEDIA:
				case HTTP_STATUS_URI_TOO_LONG:
				case HTTP_STATUS_REQUEST_TOO_LARGE:
				case HTTP_STATUS_PRECOND_FAILED:
				case HTTP_STATUS_LENGTH_REQUIRED:
				case HTTP_STATUS_GONE:
				case HTTP_STATUS_CONFLICT:
				case HTTP_STATUS_REQUEST_TIMEOUT:
				case HTTP_STATUS_PROXY_AUTH_REQ: //<-- MIRAR ESTO!!
				case HTTP_STATUS_NONE_ACCEPTABLE:
				case HTTP_STATUS_BAD_METHOD:
				case HTTP_STATUS_NOT_FOUND:
				case HTTP_STATUS_PAYMENT_REQ:
				case HTTP_STATUS_BAD_REQUEST:
					break;
				case HTTP_STATUS_FORBIDDEN:
					/*
					 if (!Ignore403) {
					 vulns++;
					 snprintf(tmp,sizeof(tmp)-1,"%s %s", vlist[i].vulnerability, "(Access Denied)");
					 UpdateHTMLReport(response,MESSAGE_WEBSERVER_VULNERABILITY_AUTHNEEDED,NULL,NULL,vlist[i].url,tmp);
					 }
					 */
					break;
				case HTTP_STATUS_DENIED:
					if (Ignore401) {
						//HACK - If the system require Authentication for all resources, we are going to test only the first one.
						if (Ignore401 > 1) {
							break;
						}
						Ignore401++;
					}
					vulns++;
					PasswordLocated = 0;

					for (k = 0; k < nUsers; k++) {
						bruteforce = SendHttpRequest(HTTPHandle, NULL,"GET",
								vlist[i].url, NULL,userpass[k].UserName,
								userpass[k].Password, response->challenge);
						if ((bruteforce) && (!ValidHTTPResponse(bruteforce))) {
							bruteforce = (PREQUEST) FreeRequest(bruteforce);
						}
						if (bruteforce) {
#ifdef _DBG_
							printf("STATUS: %i\n",bruteforce->status);
#endif
							if (bruteforce->status <= HTTP_STATUS_REDIRECT) //302
							{
								vulns++;
								snprintf(tmp, sizeof(tmp) - 1, "%s %s",
										vlist[i].vulnerability,
										"(Password Found)");
								bruteforce->status=401;
								UpdateHTMLReport(
										bruteforce,
										MESSAGE_WEBSERVER_PASSFOUND,userpass[k].UserName,
										userpass[k].Password, vlist[i].url, tmp);//, "(Password Found)");
								bruteforce = (PREQUEST) FreeRequest(bruteforce);
								PasswordLocated = 1;
								break;
							} else {
								bruteforce = (PREQUEST) FreeRequest(bruteforce);
							}
						}
					}
					if (!PasswordLocated) {
						snprintf(tmp, sizeof(tmp) - 1, "%s %s",
								vlist[i].vulnerability, "(Need Auth)");
						UpdateHTMLReport(response,
								MESSAGE_WEBSERVER_PASSFOUND,"", "",
								vlist[i].url, tmp);//, "(Password Found)");
					}

					break;
				case HTTP_STATUS_REDIRECT: //<- Mirar si hay que validar previamente!!!
					if ((response->status == HTTP_STATUS_REDIRECT)
							&& (Ignore302))
						break;
				case HTTP_STATUS_OK:
					//               if ((response->status==HTTP_STATUS_OK) && (Ignore200) ) { //IA Check
					//if ( (new_response->BufferSize==response->BufferSize) && (strcmp(new_response->lpBuffer,response->lpBuffer)==0) ) break;
					//				  if ( (new_response->BufferSize==response->BufferSize) ) break;
					if ((response->status == HTTP_STATUS_OK) && (Ignore200))
						break;

					//			   }
				case HTTP_STATUS_CREATED:
				case HTTP_STATUS_ACCEPTED:
				case HTTP_STATUS_PARTIAL:
				case HTTP_STATUS_NO_CONTENT:
				case HTTP_STATUS_RESET_CONTENT:
				case HTTP_STATUS_PARTIAL_CONTENT:
				case HTTP_STATUS_AMBIGUOUS:
				case HTTP_STATUS_MOVED:
					if ((response->status == HTTP_STATUS_MOVED) && (Ignore301)) {
						response = (PREQUEST) FreeRequest(response);
						break;
					}

					//problema con las
					if ((strstr(response->response->Data,
							vlist[i].Ignoresignature) == NULL) && (strstr(
							response->response->Header,
							vlist[i].Ignoresignature) == NULL)
							&& ((vlist[i].status == 0) || (response->status
									== vlist[i].status))) {
						if (vlist[i].nMatch == 0) {
							UpdateHTMLReport(response,
									MESSAGE_WEBSERVER_VULNERABILITY,NULL,
									NULL,vlist[i].url, vlist[i].vulnerability);
						} else
							for (j = 0; j < vlist[i].nMatch; j++) {
#ifdef _FULLDBG_
								printf("verificando nmatch[%i]: %s\n",j,vlist[i].Match[j].description);
#endif
								if ((strlen(vlist[i].Match[j].Ignorestring)
										== 0)
										|| ((strlen(
												vlist[i].Match[j].Ignorestring)
												!= 0)
												&& (strstr(
														response->response->Data ? response->response->Data
																: "",
														vlist[i].Match[j].Ignorestring)
														== NULL))) {
									for (int k = 0; k
											< vlist[i].Match[j].nstrings; k++) {
#ifdef _FULLDBG_
										printf("verificando string[%i]: %s\n",k,vlist[i].Match[j].Validatestring[k]);
#endif
										if (strstr(
												response->response->Data ? response->response->Data
														: "",
												vlist[i].Match[j].Validatestring[k])
												!= NULL) {
											vulns++;
											snprintf(
													tmp,
													sizeof(tmp) - 1,
													"%s %s",
													vlist[i].vulnerability,
													vlist[i].Match[j].description);
											UpdateHTMLReport(
													response,
													MESSAGE_WEBSERVER_VULNERABILITY,NULL,
													NULL,vlist[i].url, tmp);
											//response=FreeRequest(response);
											//                              found=1;
											break;
										}
									}
								}
							}
					}

				default:
					break;
				}
				response = (PREQUEST) FreeRequest(response);

			}
		}
	}
	/*
	 //HACK: This code seems to be misplaced... check ASAP
	 //TODO

	 if (Ignore200) {

	 new_response=FreeRequest(new_response);
	 }
	 */
	return (vulns);
}

