#ifndef _LOGSETTINGS_
#define _LOGSETTINGS_


//#include <stdio.h>
#ifdef OLD_RELEASE
#include "../HTTPCore/Build.h"
#else
#include "../../HTTPCore/Build.h"
#endif
#ifdef __WIN32__RELEASE__
	#include <windows.h>	
#else
	#include <sys/stat.h>
	#include <sys/types.h>
#endif
#include "../FHScan.h"
#include "../estructuras.h"



typedef struct _report {
	FILE *logfile;
	char header[4096*2];
	char *data;
	char end[1024];
} REPORT, *PREPORT;

//functions
int CloseHTMLReport(void);
//int UpdateHTMLReport(struct _request *data, int FROM);
int UpdateHTMLReport(struct _request *data,int FROM, char *username, char *password, char *url, char *VulnDescription);
int InitHTMLReport(
 char *path,
 unsigned long currentip,
 unsigned long endip,
 int nports,
 struct _ports *ports,
 int nthreads,
 int bruteforce,
 int fulluserlist,
 int vulnchecks);

 /*
 int PrintResult(struct _request *data, int FROM) ;
void UpdateData(struct _request *data, char *username, char *password, char *Vuln, char *VulnDescription);
*/

#define MESSAGE_FINGERPRINT			0
#define MESSAGE_ROUTER_FOUND 		1
#define MESSAGE_WEBSERVER_FOUND		2
#define MESSAGE_ROUTER_PASSFOUND	3
#define MESSAGE_WEBFORM_PASSFOUND	3

#define MESSAGE_WEBFORMS_PASSNOTFOUND 4

#define MESSAGE_ROUTER_NOPASSWORD 5




#define MESSAGE_WEBSERVER_VULNERABILITY_AUTHNEEDED 6
#define MESSAGE_WEBSERVER_PASSFOUND  6
#define MESSAGE_WEBSERVER_VULNERABILITY 6


//#define MESSAGE_WEBFORM_AUTH      10






#endif
