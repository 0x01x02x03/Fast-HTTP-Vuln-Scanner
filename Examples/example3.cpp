//Simple HTTP API example. 
//Example2 - Authentication example II

/* Its possible to use an username / password without knowing if the remote host needs authentication.
If the remote host requests authentication the specified username and password will be sent 
*/

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
        printf(" Requesting the remote resource \n");
        data=SendHttpRequest(HTTPHandle,server,"GET",url,PostData,"username","password",NO_AUTH);
        if (data) {
            if (data->status != 401 ){ //Need Auth
                    printf("Resource not protected or valid username and password\n");
            } else {
                    printf("Invalid username or password\n");
            }
            FreeRequest(data);
        }
        CloseHTTPConnectionHandle(HTTPHandle);
    } else {
        printf("[-] Unable to resolve remote host\n");
    }
    CloseHTTPApi();
}