#ifndef _DIGEST_
#define _DIGEST_
//#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <string.h>
#ifdef __WIN32__RELEASE__
#include <windows.h>
#endif

char *CreateDigestAuth(char *AuthenticationHeader, char *lpUsername, char *lpPassword, char *method,char *uri, int counter);

#endif

