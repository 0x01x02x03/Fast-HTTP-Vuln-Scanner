//Simple HTTP API example.
//Example1: Make a simple HTTP Request


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
        data=SendHttpRequest(HTTPHandle,server,"GET",url,PostData,NULL,NULL,NO_AUTH);
        if (data) {

	    printf("Request Headers:\n%s",data->request->Header);
	    printf("Request Data:\n%s\n", data->request-Data);

            if (data->response) {
		printf("Basic Information from server:\n");
		printf("------------------------------\n");
                printf("Remote HTTP Server:      %s\n",data->server);
                printf("Remote HTTP Status Code: %s\n",data->status);

                printf("Response Headers:\n%s",data->request->Header);
	    	printf("Response Data:\n%s\n", data->request-Data);

            }
            FreeRequest(data);
        }
        CloseHTTPConnectionHandle(HTTPHandle);
    }
    CloseHTTPApi();
}