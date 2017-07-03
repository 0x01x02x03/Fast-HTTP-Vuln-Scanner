#ifndef _WEBSERVERS_H
#define __WEBSERVERS_H

#include "FHScan.h"
#include "estructuras.h"
int CheckVulnerabilities(HTTPHANDLE HTTPHandle, struct _request *data,int nLogins, USERLIST *userpass);

#endif
