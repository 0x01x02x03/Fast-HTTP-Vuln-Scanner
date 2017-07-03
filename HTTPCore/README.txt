FSCAN HTTP Core Library
-------------------------


You can download the lastest build version from http://www.tarasco.org however if you 
like to build your own library, you can follow these instructions:



First of all you need to create a directory named for example c:\Fscan-Binary



Codegear Rad Studio ( Borland C++ Builder )
-----------------------------------------------
//TODO


Visual Studio 2008:
--------------------

Create a new empty win32 console project, and check the option library. Add The files from this package to that project.

Follow the next steps:

1)- Download lastest Zlib libraries from http://www.gzip.org/zlib/zlib123-dll.zip and extract zconf.h and zlib.h into FScan Core Directory.
Drop the zdll.lib and zdll1.dll into c:\Fscan-Binary.

2)- Download Lastest OpenSSL binaries (Win32OpenSSL-0_9_8h.exe ) from http://www.slproweb.com/products/Win32OpenSSL.html and add "C:\OpenSSL\include" to your visual studio project path.
Drop libeay32.lib and ssleay32.lib to c:\Fscan-Binary

3) Add the follogin defines to the project (properties > Configuration properties > c/c++ > Preprocesor > Preprocesor Definitions: __WIN32__RELEASE__;_MULTITHREADING_; _ZLIB_SUPPORT_;_OPENSSL_SUPPORT_

4) Compile the application, the file Release\FscanHTTPCore.lib will be generated.

5) Copy the resultant FscanHTTPCore.lib to c:\Fscan-Binary


Linux gcc (tested with g++ v4.1..2 under Debian 4.1.1-21):
----------------------------------------------------------
g++  -DLINUX  -D_OPENSSL_SUPPORT_ -D_ZLIB_SUPPORT_ -D_MULTITHREADING_ -c -fPIC HTTPCore/*.cpp HTTPCore/Authentication/*.cpp HTTPCore/Modules/*.cpp
g++ -shared -o HTTPCore.so -fPIC HTTPCore/*.o
g++  -lpthread -lssl -DLINUX  -D_OPENSSL_SUPPORT_ -D_ZLIB_SUPPORT_ -D_MULTITHREADING_ Fscan/*.cpp Fscan/Reporting/*.cpp HTTPCore.so -o Fscan


Testing:
---------

To use the new library with your own application just:

a) copy all files from c:\Fscan-Binary to the application folder.
b) add and "#include "HTTP.h" to the main cpp file
c) Add #pragma comment(lib, "FscanHTTPCore.lib") in your source code.
d) Compile and enjoy ;)

An example of a test application is:

#include <stdio.h>
#include <windows.h>
#include "http.h"

#pragma comment(lib, "FscanHTTPCore.lib")

void main(int argc, char *argv[])
{
    
     HTTPHANDLE HTTPHandle;
     PREQUEST data;

    InitHTTPApi();
    
    HTTPHandle=InitHTTPConnectionHandle(argv[1],80,PROTOCOL_TCP_HTTP);
    if (!HTTPHandle) return;

    data=SendHttpRequest(HTTPHandle,argv[1],"GET",argv[2],NULL,NULL,NULL,NO_AUTH);
    if (data) {
	if (data->response) {
	  printf("Read: %s\nData\n%s",data->response->Header,data->response->Data);
	}
	FreeRequest(data);
    }
    CloseHTTPConnectionHandle(HTTPHandle);
    CloseHTTPApi();
}

