#include "FHScan.h"
#include "config.h"

typedef struct update{
	int Mayor;
	int Minor;
	int Build;
	int signature;

	char host[256];
	int port;
	int ssl;
	char version_url[256];
	char package_url[256];
	char signature_url[256];
	char *news;
	char linux_url[256];
} UPDATE;

int CheckConfigFile(char *filename,UPDATE *local)
{
	FILE *update=fopen(filename,"r");
	char line[1024];
	if (!update)
	{
		return(0);
	}
	while (!feof(update))
	{
			if ( ReadAndSanitizeInput(update,line,sizeof(line)) ){
				if (memcmp(line,"FHSCAN_MAYOR_VERSION= ",21)==0)
				{
					local->Mayor=atoi(line+21+1);
				}
				if (memcmp(line,"FHSCAN_MINOR_VERSION= ",21)==0)
				{
					local->Minor=atoi(line+21+1);
				}
				if (memcmp(line,"FHSCAN_BUILD_VERSION= ",21)==0)
				{
					local->Build=atoi(line+21+1);
				}
				if (memcmp(line,"FHSCAN_SIGNATUREFILE= ",21)==0)
				{
					local->signature=atoi(line+21+1);
				}
	//----
				if (memcmp(line,"FHSCAN_UPDATE_SERVER= ",21)==0)
				{
					strcpy(local->host,line+21+1);
				}
				if (memcmp(line,"FHSCAN_UPDATE_PORT__= ",21)==0)
				{
					local->port=atoi(line+21+1);
				}
				if (memcmp(line,"FHSCAN_PROTOCOL_PORT= ",21)==0)
				{
					local->ssl=atoi(line+21+1);
				}
				if (memcmp(line,"FHSCAN_CHECK_VERSION= ",21)==0)
				{
					strcpy(local->version_url,line+21+1);
				}
				if (memcmp(line,"FHSCAN_DWNLD_PACKAGE= ",21)==0)
				{
					strcpy(local->package_url,line+21+1);
				}
				if (memcmp(line,"FHSCAN_SIGNATUREFILE= ",21)==0)
				{
					strcpy(local->signature_url,line+21+1);
				}
				if (memcmp(line,"FSCAN_DOWNLOAD_LINUX= ",21)==0)
				{
					strcpy(local->linux_url,line+21+1);
				}

				if (memcmp(line,"FSCAN_UPDATE_NEWS___= ",21)==0)
				{
					local->news=_strdup(line+21+1);
				}

			}

	}

	fclose(update);
	return(1);

}
int UpdateFHScan(void) 
{
	FILE *update;
//	char buf[4096];
	char tmp[256];

	HTTPHANDLE HTTPHandle;
	HTTPHANDLE NEWHTTPHandle;

	PREQUEST DATA;
	PREQUEST DOWNLOAD;
	UPDATE local,remote;
//	char *p;
	int ret;
	int completeupdate=0;


	ret=CheckConfigFile("FHSCAN_release.dat",&local);
	if (!ret)
	{
		printf("[-] Unable to locate FHSCAN_release.dat. Please manually check for updates at http://www.tarasco.org\n");
		return(1);
	}
	
	printf("[+] Installed FHScan Build: %i.%i.%i\n",local.Mayor,local.Minor,local.Build);

	//InitHTTPApi();
	printf("[+] Connecting with: %s:%i SSL: %i\n",local.host,local.port,local.ssl);
	HTTPHandle=InitHTTPConnectionHandle(local.host,local.port,local.ssl);
	if (HTTPHandle == NULL)
	{
		printf("[-] Unable to resolve %s\n",local.host);
		return(1);
	}

	DATA=SendHttpRequest(HTTPHandle,NULL,"GET",local.version_url,NULL,NULL,NULL,NO_AUTH);
	if ((!DATA) || (!DATA->response) )
	{
		printf("[-] Request error\n");
		return(1);
	}
	if ( (DATA->status!=200) || (DATA->response->DataSize==0) )
	{
		printf("[-] Unable to locate http%s://%s%s:%i \n",local.ssl ? "s": "", local.host,local.version_url,local.port);
		return(1);
	}
	update=fopen("tmp.dat","w");
	fwrite(DATA->response->Data,1,DATA->response	->DataSize,update);
	fclose(update);

	ret=CheckConfigFile("tmp.dat",&remote);

	if ( (remote.Mayor >local.Mayor) || (remote.Minor > local.Minor) || remote.Build >local.Build )
	{
		printf("[+] Current FHScan Build: %i.%i.%i\n",remote.Mayor,remote.Minor,remote.Build);
		printf("[+] Downloading http%s://%s%s:%i \n",remote.ssl ? "s": "", remote.host,remote.package_url,remote.port);
		if (remote.news) {
			printf("[+] News: %s\n",remote.news);
		}
		NEWHTTPHandle=InitHTTPConnectionHandle(remote.host,remote.port,remote.ssl);
#ifdef __WIN32__RELEASE__
		DOWNLOAD=SendHttpRequest(NEWHTTPHandle,NULL,"GET",remote.package_url,NULL,NULL,NULL,NO_AUTH);		
#else
		DOWNLOAD=SendHttpRequest(NEWHTTPHandle,NULL,"GET",remote.linux_url,NULL,NULL,NULL,NO_AUTH);
#endif
		if ( (DOWNLOAD) && (DOWNLOAD->response) && (DOWNLOAD->response->DataSize) )
		{
#ifdef __WIN32__RELEASE__
			sprintf(tmp,"FHScan_%i.%i.%i.zip",remote.Mayor,remote.Minor,remote.Build);
#else
			sprintf(tmp,"FHScan-%i.%i.%i-i386-Backtrack3.tgz",remote.Mayor,remote.Minor,remote.Build);
#endif
			printf("[+] Saving file as: %s  (please extract it manually)\n",tmp);
			update=fopen(tmp,"wb");
			fwrite(DOWNLOAD->response->Data,1,DOWNLOAD->response->DataSize,update);
			fclose(update);
			printf("[+] Saving FHSCAN_release.dat\n");
			update=fopen("FHSCAN_release.dat","w");
			fwrite(DATA->response->Data,1,DATA->response->DataSize,update);
			fclose(update);
			FreeRequest(DATA);
			FreeRequest(DOWNLOAD);
			CloseHTTPConnectionHandle(HTTPHandle);
			CloseHTTPConnectionHandle(NEWHTTPHandle);
			CloseHTTPApi();
			completeupdate=1;
		} else {
			printf("[-] Unable to download FHScan file\n");
		}
		return(0);

	}

	if ( ( remote.signature > local.signature ) && (!completeupdate) )
	{
		printf("[+] Current FHScan Build: %i.%i.%i Signature: %i\n",remote.Mayor,remote.Minor,remote.Build,remote.signature);
		printf("[+] Downloading http%s://%s%s:%i \n",remote.ssl ? "s": "", remote.host,remote.signature_url,remote.port);
		NEWHTTPHandle=InitHTTPConnectionHandle(remote.host,remote.port,remote.ssl);
		DOWNLOAD=SendHttpRequest(NEWHTTPHandle,NULL,"GET",remote.signature_url,NULL,NULL,NULL,NO_AUTH);
		if ( (DOWNLOAD) && (DOWNLOAD->response) && (DOWNLOAD->response->DataSize) && (DOWNLOAD->status==200) )
		{
			sprintf(tmp,"FHScan_signature_%i.%i.%i_%i.zip",remote.Mayor,remote.Minor,remote.Build,remote.signature);
			printf("[+] Saving file as: %s (please extract it manually)\n",tmp);
			update=fopen(tmp,"w");
			fwrite(DOWNLOAD->response->Data,1,DOWNLOAD->response->DataSize,update);
			fclose(update);
			printf("[+] Saving FHSCAN_release.dat\n");
			update=fopen("FHSCAN_release.dat","w");
			fwrite(DATA->response->Data,1,DATA->response->DataSize,update);
			fclose(update);
			FreeRequest(DATA);
			FreeRequest(DOWNLOAD);
			CloseHTTPConnectionHandle(HTTPHandle);
			CloseHTTPConnectionHandle(NEWHTTPHandle);
			CloseHTTPApi();

		} else {
			printf("[-] Unable to download FHScan siagnature file\n");
		}
		return(0);

	}

	printf("[+] FHScan is up to date. Enjoy =) \n");
	FreeRequest(DATA);
	CloseHTTPConnectionHandle(HTTPHandle);


	CloseHTTPApi();
	return(0);


}
