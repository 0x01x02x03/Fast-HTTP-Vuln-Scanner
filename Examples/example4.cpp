//Simple HTTP API example. 
//Example4 - Using special parameters with HTTP Requests


#include <stdio.h>
#include "HTTP.h"

#ifdef _WIN32
#include <windows.h>
#pragma comment(lib, "HTTPCore.lib")
#endif

void main(int argc, char *argv[])
{

    HTTPHANDLE HTTPHandle; /*Connection HANDLE */
    PREQUEST data;
    const char server[]="www.google.com";
    const char url[] = "/";
    unsigned int ssl = 0;
    char  *PostData  = NULL;

    InitHTTPApi();

    HTTPHandle=InitHTTPConnectionHandle(server,80,ssl);
    if (HTTPHandle)
    {
        int ret;
        ret = SetHTTPConfig(HTTPHandle,OPT_HTTP_PROXY_HOST,"proxy.dmz.local");
        if (!ret) {
            printf("Unable to resolve remote proxy Host\n");
            return;
        }
        SetHTTPConfig(HTTPHandle,OPT_HTTP_PROXY_PORT,"8080");

        printf(" Requesting the the HTTP resource using an HTTP PRoxy ¨Server\n");
        data=SendHttpRequest(HTTPHandle,server,"GET",url,PostData,NULL,NULL,NO_AUTH);
        if (data) {
            if (data->response)
            {
                printf("Resource gathered: %s\n",data->response->Data);
            }
            FreeRequest(data);
        }
        CloseHTTPConnectionHandle(HTTPHandle);
    } else {
        printf("[-] Unable to resolve remote host\n");
    }
    CloseHTTPApi();
}