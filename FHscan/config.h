#ifndef __CONFIGURATION_FILE
#define __CONFIGURATION_FILE

#include "FHScan.h"

#include <stdio.h>
#ifdef __WIN32__RELEASE__
 #include <windows.h>
#endif

int LoadConfigurationFiles(int argc, char *argv[]);
int LoadKnownWebservers(char *path);
int LoadKnownRouters(char *path);
int LoadWebForms(char *path);
int LoadUserList(char *path);
int LoadSingleUserList(char *path);
int LoadIgnoreList(char *path);
int LoadWebservers(char *path) ;
int LoadRouterAuth(char *path) ;
int ReadAndSanitizeInput(FILE *file, char *buffer,int len); 

#endif
