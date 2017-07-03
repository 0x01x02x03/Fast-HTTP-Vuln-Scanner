/*
Fast HTTP Auth Scanner - Logsettings.cpp
Creates HTML reports from tmpl.dat template

TODO:
- Rellenar la variable $FRECORDS con los parametros de cada fichero
*/


//#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>

#include "../FHScan.h"
#include "LogSettings.h"

CRITICAL_SECTION lock;
#ifdef __WIN32__RELEASE__
SYSTEMTIME LogTime;
#else
#include <sys/stat.h>
#include <sys/types.h>
struct tm *LogTime;
#endif


PREPORT report=NULL;
char files[][20]={ "index.html","devices.html","webservers.html","routerswp.html","routersup.html","routersnp.html","bruteforce.html" };
char descs[][50]= {"Open ports","Devices","webservers","Routers with password","routers with unknown password","routers without password","Web vulnerabilities"};

extern FILE   *ipfile;
extern int ShowAllhosts;
extern int csv;
char DirectoryLog[MAX_PATH+1]="";
//extern FILE *LogFile;
//extern FILE *LogFiledebug;

/**************************************************************************/
int CloseHTMLReport(void) {
//return (0);
	DeleteMutex(&lock);
	if (report) {
		for(int i=0;i<7;i++) {
			if (report[i].logfile)
			{
				fwrite(report[i].end,1,strlen(report[i].end),report[i].logfile);
				fclose(report[i].logfile);
			}
		}
		free(report);
		return(1);
	}
	return(0);
}
/**************************************************************************/
//int UpdateHTMLReport(struct _request *data, int FROM)
/**************************************************************************/
//http://www.cert.org/tech_tips/cgi_metacharacters.html
#if 0
void FixXSS(char *data, char *dst) {
	char *q;
	static char ok_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.@ ";
	if (data)
    *dst='\0';
}
#endif

#define  ok_chars "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.@ "
//__inline static void FixXSS(char *data) {while (*(data++)) { char *q=strchr(ok_chars,*data); *data=(q) ? *q :'_' ; }   }
/**************************************************************************/
/*******************************************************************************/
static int GetHtmlTitle(struct _request *data, char *output, unsigned int dstSize) {

    char *p,*q;
	char *buffer;
	unsigned int BufferSize;// = (unsigned int ) strlen(buffer);

	buffer=data->response->Data;
	BufferSize = (unsigned int ) strlen(buffer);

	if ( (buffer) && BufferSize>15) {
        for (unsigned int i=0;i<BufferSize-14;i++)
        {
			if (strnicmp(buffer+i,"<title",6)==0)
			{
				memset(output,'\0',dstSize);
				p = strchr(buffer+i+6,'>');
				if (p){					
					p++;
					q=strchr(p,'<');
					memset(output,0,dstSize);
					if (q) {
						
						while ( (*p=='\r') || (*p=='\n') || (*p==' ') ) p++;
						if ( (q-p)<dstSize) memcpy(output,p,q-p);
						else            memcpy(output,p,dstSize-1);
					} else {
						BufferSize = ( unsigned int )strlen(p);
						if (BufferSize>dstSize)
						{
							memcpy(output,p,dstSize-1);
						} else {
							memcpy(output,p,BufferSize);
						}
					}
					return(1);
				}
			}
        }
	}

	if ( (data->status==401) )
	{
			char *lpTitle=GetHeaderValue(data->response->Header,"WWW-Authenticate: Basic",0);
			if (lpTitle)
			{
				char *realm=strstr(lpTitle,"realm=\"");
				if (realm){
					realm+=7;
					char *q=strchr(realm,'\"');
					if (q)
					{
						*q=0;
						memset(output,0,dstSize);
						strncpy(output,realm,dstSize-1);
						free(lpTitle);
						return(1);
					}

				}
				free(lpTitle);
			}
	}
	*output='\0';
	return(0);
}
/*******************************************************************************/
int UpdateHTMLReport(struct _request *data,int FROM, char *UserName, char *Password, char *url, char *VulnDescription)
{
//     return (0);

	char buffer[4096]="";
	char tmp[2048];
	int j=0;
	char *p;

	if ( (!data) || (!report)) {
		return(0);
	}



	if (report)
	{
		LockMutex(&lock);
		char title[512];
		//memset(tmp,0,sizeof(tmp));
		//memset(buffer,0,sizeof(buffer));
		//memset(title,0,sizeof(title));

		
		GetHtmlTitle(data,(char*)title,sizeof(title));


		snprintf(buffer,sizeof(buffer)-1,"   <tr> <td><a href=\"%s://%s:%i%s\" target=\"_blank\">+</a>%s</td> <td>%i</td> <td>%i</td> <td>%s</td>",data->NeedSSL ? "https" : "http" ,data->hostname,data->port,url ? url : "/",data->hostname,data->port,data->status,title);
		fwrite(buffer,1,strlen(buffer),report[FROM].logfile);

		
		switch(FROM)
		{

		case MESSAGE_FINGERPRINT:
			if (ShowAllhosts) {
				if (csv) {
					fprintf(stdout,"FPRINT|%s|%i|%i|%s|%s\n",data->hostname,data->port,data->status,title,data->server);
				} else {
					printf("FPRINT: %15s %3i %3i %s\n",data->hostname,data->port,data->status,data->server);
				}
			}
			break;
		case MESSAGE_ROUTER_FOUND:
			if (csv) {
					fprintf(stdout,"ROUTER|%s|%i|%i|%s|%s\n",data->hostname,data->port,data->status,title,data->server);
			} else {
				printf("ROUTER: %15s %3i %3i %s\n",data->hostname,data->port,data->status,data->server);
			}
			break;
		case MESSAGE_WEBSERVER_FOUND:
			if (csv) {
					fprintf(stdout,"WEBSRV|%s|%i|%i|%s|%s\n",data->hostname,data->port,data->status,title,data->server);
			} else {
				printf("WEBSRV: %15s %3i %3i %s\n",data->hostname,data->port,data->status,data->server);
			}
			break;
		case MESSAGE_ROUTER_PASSFOUND:
//		case MESSAGE_WEBFORM_PASSFOUND:
			snprintf(buffer,sizeof(buffer)-1,"<td>%s</td> <td>%s</td> <td>%s</td> ",(UserName!=NULL) ? UserName : "",(Password!=NULL) ? Password : "",url);
			fwrite(buffer,1,strlen(buffer),report[FROM].logfile);

			if (csv) {
					fprintf(stdout,"RTPASS|%s|%i|%i|%s|%s|%s|%s|%s\n",data->hostname,data->port,data->status,title,(UserName!=NULL) ? UserName : "",(Password!=NULL) ? Password : "",url,data->server);
			} else {
				printf("RTPASS: %15s %3i %3i %s %s %s %s\n",data->hostname,data->port,data->status,(UserName!=NULL) ? UserName : "",(Password!=NULL) ? Password : "",url,data->server);
			}
			break;
		case MESSAGE_WEBFORMS_PASSNOTFOUND:  //router 401 & webform authentication

			snprintf(buffer,sizeof(buffer)-1,"<td>%s</td> ",url);
			fwrite(buffer,1,strlen(buffer),report[FROM].logfile);
			if (csv) {
					fprintf(stdout,"RUPASS|%s|%i|%i|%s|%s|%s\n",data->hostname,data->port,data->status,title,url,data->server);
			} else {
				printf("RUPASS: %15s %3i %3i %s %s\n",data->hostname,data->port,data->status,url,data->server);
			}
			break;
		case MESSAGE_ROUTER_NOPASSWORD:
			if (csv) {
					fprintf(stdout,"RNPASS|%s|%i|%i|%s|%s\n",data->hostname,data->port,data->status,title,data->server);
			} else {
				printf("RNPASS: %15s %3i %3i %s\n",data->hostname,data->port,data->status,data->server);
			}
			break;
		case MESSAGE_WEBSERVER_VULNERABILITY:
//		case MESSAGE_WEBSERVER_VULNERABILITY_AUTHNEEDED:
//		case MESSAGE_WEBSERVER_PASSFOUND:
			snprintf(buffer,sizeof(buffer)-1,"<td>%s</td> <td>%s</td> <td>%s</td> <td>%s</td> ",url,(UserName!=NULL) ? UserName : "",(Password!=NULL) ? Password : "",(VulnDescription!=NULL) ? VulnDescription : "");
			fwrite(buffer,1,strlen(buffer),report[FROM].logfile);

			if (csv) {
					fprintf(stdout,"WEBVUL|%s|%i|%i|%s|%s|%s|%s|%s|%s\n",data->hostname,data->port,data->status,title,(UserName!=NULL) ? UserName : "",(Password!=NULL) ? Password : "",url,(VulnDescription!=NULL) ? VulnDescription : "",data->server);
			} else {
				printf("WEBVUL: %15s %3i %3i %s %s %s %s %s\n",data->hostname,data->port,data->status,(UserName!=NULL) ? UserName : "",(Password!=NULL) ? Password : "",url,(VulnDescription!=NULL) ? VulnDescription : "",data->server);
			}
			break;
		default:
			UnLockMutex(&lock);
			return 0;
		}
			if ((VulnDescription) && ( (FROM == MESSAGE_WEBFORM_PASSFOUND) || (FROM == MESSAGE_ROUTER_PASSFOUND) || (FROM == MESSAGE_WEBFORM_PASSFOUND) || (FROM == MESSAGE_WEBFORMS_PASSNOTFOUND)) )
			{
				sprintf(tmp," (%s)",VulnDescription);
			} 	else tmp[0]='\0';
			snprintf(buffer,sizeof(buffer)-1,"<td id=\"IP%s\" onmouseover=\"testfunc(this.id);\" onmouseout=\"setVisibility('foo','none');\">%s %s ",data->hostname,data->server,tmp);
			fwrite(buffer,1,strlen(buffer),report[FROM].logfile);
			snprintf(buffer,sizeof(buffer)-1,"<div id=\"headers_IP%s\" class=\"hideme\"> ",data->hostname);
			fwrite(buffer,1,strlen(buffer),report[FROM].logfile);

			while (	p=GetHeaderValueByID(data->response->Header,j++) ){
				fwrite(p,1,strlen(p),report[FROM].logfile);
				fwrite("<br/>",1,5,report[FROM].logfile);
				free(p);
			}
			fwrite("</div></td>",1,11,report[FROM].logfile);
			fwrite("</tr>\n",1,6,report[FROM].logfile);

			fflush( report[FROM].logfile);
			fflush(stdout);


		UnLockMutex(&lock);
		return(1);
	}
	return(0);

}
/**************************************************************************/

int InitHTMLReport(
				   char *path,
				   unsigned long currentip,
				   unsigned long endip,
				   int nports,
struct _ports *ports,
	int nthreads,
	int bruteforce,
	int fulluserlist,
	int vulnchecks) {

//return(0);
		InitMutex(&lock);

#ifdef __WIN32__RELEASE__
		GetLocalTime(&LogTime);
#else
		time_t currenttime;
		char fecha[256];
		time(&currenttime);
		LogTime=gmtime(&currenttime);
#endif


		report=(PREPORT)malloc(sizeof(REPORT)*7);
		memset(report,'\0',   sizeof(REPORT)*7);

		FILE *TemplateHTML=fopen("tmpl.dat","r");
		if (!TemplateHTML) {
			if (!csv) {
				printf("[-] Error Loading tmpl.dat\n");
			}
			free(report); report=NULL;
			return(0);
		}
		if (TemplateHTML) {
			char tmp[4096*2];
			unsigned int readbytes;
			int total=0;
			char *lpHTML=NULL;
#ifdef __WIN32__RELEASE__
			if (!*DirectoryLog) snprintf(DirectoryLog,sizeof(DirectoryLog),".\\%4.4i-%2.2i-%2.2i--%2.2i%2.2i%2.2i",LogTime.wYear,LogTime.wMonth,LogTime.wDay,LogTime.wHour,LogTime.wMinute,LogTime.wSecond);
			CreateDirectoryA((char*)DirectoryLog,NULL);
#else
			if (!*DirectoryLog)  strftime(DirectoryLog,sizeof(DirectoryLog)-1,"./%Y-%m-%d--%H%M%S",LogTime);
			mkdir(DirectoryLog,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

#endif
#ifdef __WIN32__RELEASE__

#else

#endif
			//Read HTML Template
			while (!feof(TemplateHTML)) {
				memset(tmp,'\0',sizeof(tmp));
				readbytes=(unsigned int)fread(tmp,1,sizeof(tmp)-1,TemplateHTML);
				//				printf("leidos: %i - Total: %i\n",readbytes,total);
				lpHTML=(char *)realloc((char *)lpHTML,total+readbytes+1);
				memcpy(lpHTML+total,tmp,readbytes);
				total+=readbytes;
				lpHTML[total]='\0';
			}
			char *opt;
			//Generate HTML Head from Template
			char *where=lpHTML;
			do {
				opt=strchr(where,'$');
				/*			printf("***DEBUG: ");
				for(int i=0;i<40;i++) printf("%c",opt[i]);
				printf("\n\n");
				*/
				if (opt) {
					for(int i=0;i<7;i++) strncat(report[i].header,where,opt-where);
					if (strncmp(opt+1,"HOSTPATH",8)==0)
					{
						if (path!=NULL)
						{
							//snprintf(tmp,sizeof(tmp)-1,"<a href=\"file:\\\\%s\" target=\"_blank\">%s</a>",path,path);
							//printf("copiando: %s\n",tmp);
							//strcat(report[0].header,tmp);
							for(int i=0;i<7;i++) strcat(report[i].header,path);
							//						printf("queda: %s\n",report[0].header);
						} else
						{
							struct sockaddr_in client;
							client.sin_addr.s_addr=htonl(currentip);
							snprintf(tmp,sizeof(tmp)-1," %s",inet_ntoa(client.sin_addr));
							for(int i=0;i<7;i++) strcat(report[i].header,tmp);
							if (currentip +1 != endip) {
								for(int i=0;i<7;i++) strcat(report[i].header," - ");
								client.sin_addr.s_addr=htonl(endip);
								for(int i=0;i<7;i++) strcat(report[i].header,inet_ntoa(client.sin_addr));
							}
						}
					} else
						if (strncmp(opt+1,"SCANDATE",8)==0)
						{
	#ifdef __WIN32__RELEASE__
									snprintf(tmp,sizeof(tmp)-1,"%i/%i/%i - %i:%i ",LogTime.wMonth,LogTime.wDay,LogTime.wYear,LogTime.wHour,LogTime.wMinute);
#else
									strftime(tmp,sizeof(tmp)-1,"./%m/%d/%Y  - %H%M",LogTime);
#endif
									for(int i=0;i<7;i++) strcat(report[i].header,tmp);
						} else

						if (strncmp(opt+1,"HTTPPORT",8)==0)
						{
							for(int j=0;j<nports;j++)
							{
								if (j!=0) for(int i=0;i<7;i++) strcat(report[i].header," / ");
								if (!ports[j].ssl) {
									snprintf(tmp,sizeof(tmp)-1,"HTTP %i",ports[j].port);
								} else {
									snprintf(tmp,sizeof(tmp)-1,"HTTPS %i",ports[j].port);
								}
									for(int i=0;i<7;i++) strcat(report[i].header,tmp);

							}
						} else

								if (strncmp(opt+1,"NTHREADS",8)==0)
								{
									snprintf(tmp,sizeof(tmp)-1,"%i",nthreads);
									for(int i=0;i<7;i++) strcat(report[i].header,tmp);
									//strcat(report[i].header,"1");

								}
								if (strncmp(opt+1,"BRUTEFOR",8)==0)
								{
									if (bruteforce) {
										for(int i=0;i<7;i++) strcat(report[i].header,"class=\"input\" >BruteForce");
									} else {
										for(int i=0;i<7;i++) strcat(report[i].header,"class=\"inputstrike\" >BruteForce");
									}
								} else
									if (strncmp(opt+1,"FULLUSER",8)==0)
									{
										if (fulluserlist) {
											for(int i=0;i<7;i++) strcat(report[i].header,"class=\"input\" >Full Users list");
										} else {
											for(int i=0;i<7;i++) strcat(report[i].header,"class=\"input\" > Simple Users List");
										}
									} else
										if (strncmp(opt+1,"VULNCHEC",8)==0)
										{
											if (vulnchecks) {
												for(int i=0;i<7;i++) strcat(report[i].header,"class=\"input\" >Vulnerability Checks");
											} else {
												for(int i=0;i<7;i++) strcat(report[i].header,"class=\"inputstrike\" >Vulnerability Checks");
											}

										} else
											if (strncmp(opt+1,"FOPTIONS",8)==0)
											{
												for (int i=1; i < 7; i++) {
													strncpy(report[i].header,report[i].header,sizeof(report[i].header)-1);
												}
												for(int i=0;i<7;i++)
												{
													for(int j=0;j<7;j++) {
														if (i==j) {
															snprintf(tmp,sizeof(tmp)-1,"  <li><a class=\"active\" href=\"%s\">%s</a></li>\n",files[j],descs[j]);
														} else {
															snprintf(tmp,sizeof(tmp)-1,"  <li><a href=\"%s\">%s</a></li>\n",files[j],descs[j]);
														}
														strcat(report[i].header,tmp);
													}
												}
											} else
												if (strncmp(opt+1,"FRECORDS",8)==0) {
													for(int i=0;i<7;i++) {
														//if (i!=0) strncat(report[i].header,where,opt-where);
														//Shared columns
														strcat(report[i].header,"    <td width=\"100\" height=\"20\" class=\"field\">host</td>\n");
														strcat(report[i].header,"    <td width=\"40\" class=\"field\">port</td>\n");
														strcat(report[i].header,"    <td width=\"90\" class=\"field\">status code </td>\n");
														strcat(report[i].header,"    <td width=\"150\" class=\"field\">HTML Title </td>\n");

														switch(i) {
															case 0:
															case 1:
															case 2:
															case 5:
																strcat(report[i].header,"    <td class=\"field\">banner</td>\n");
																break;
															case 3:
																strcat(report[i].header,"    <td class=\"field\">user</td>\n");
																strcat(report[i].header,"    <td class=\"field\">password</td>\n");
																strcat(report[i].header,"    <td class=\"field\">path</td>\n");
																strcat(report[i].header,"    <td class=\"field\">banner</td>\n");
																break;
															case 4:
																strcat(report[i].header,"    <td width=\"150\" class=\"field\">path</td>\n");
																strcat(report[i].header,"    <td width=\"139\" class=\"field\">banner</td>\n");
																break;
															case 6:
																strcat(report[i].header,"    <td width=\"94\" class=\"field\">path</td>\n");
																strcat(report[i].header,"    <td width=\"58\" class=\"field\">user</td>\n");
																strcat(report[i].header,"    <td width=\"70\" class=\"field\">password</td>\n");
																strcat(report[i].header,"    <td width=\"194\" class=\"field\">description</td>\n");
																strcat(report[i].header,"    <td width=\"148\" class=\"field\">banner</td>\n");
																break;
														}

													}
												} else
													//END OF HEADER - WRITE TAIL INFORMATION
													if (strncmp(opt+1,"RECORDDT",8)==0)
													{
														for(int i=0;i<7;i++) {
															//char foo[1024];
															//printf("END(%i): %s\n-------------\n",i,opt+9);
															strncpy(report[i].end,opt+9,sizeof(report[i].end)-1);
#ifdef __WIN32__RELEASE__
															snprintf(tmp,sizeof(tmp)-1,"%s\\%s",DirectoryLog,files[i]);
#else
															snprintf(tmp,sizeof(tmp)-1,"%s/%s",DirectoryLog,files[i]);
#endif
															//printf("Abriendo: %s\n",tmp);
															report[i].logfile=fopen(tmp,"w");
															if (!report[i].logfile) {
																free(report);
																report=NULL;
																return(0);
															}
															fwrite(report[i].header,1,strlen(report[i].header),report[i].logfile);
															fflush(report[i].logfile);
														}
														free(lpHTML);
														fclose(TemplateHTML);
														return(1);
													}
													where=opt+9;
				} else {
					for(int i=0;i<7;i++) strncat(report[i].header,where,strlen(where));
				}
			} while (opt);
			free(lpHTML);
			fclose(TemplateHTML);
			return(1);
		}

		return(1);
}
/***************************************************************/


