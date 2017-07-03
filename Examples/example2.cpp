//Simple HTTP API example. 
//Example2 - Authentication example I


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
            if (data->status == 401 ){ //Need Auth
                int auth= data->challenge;
                FreeRequest(data);
                data=SendHttpRequest(HTTPHandle,server,"GET",url,PostData,"username","password",auth);
                if ((data) && (data->status !=401)
                {
                    printf("Client Authentication succeed against %s\n",data->hostname);                    
                } else {
                    printf("Invalid username or password\n");
                }
                FreeRequest(data);
            } else {
                printf("The remote host does not need authentication\n");
            }
        }
        CloseHTTPConnectionHandle(HTTPHandle);
    } else {
        printf("[-] Unable to resolve remote host\n");
    }
    CloseHTTPApi();
}