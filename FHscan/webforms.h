#ifndef __WEBFORMS_H
#define __WEBFORMS_H
#include <stdio.h>
#ifdef __WIN32__RELEASE__
#include <windows.h>
#endif


#define RAWUSER   "!!!RAWUSER!!!"
#define RAWPASS   "!!!RAWPASS!!!"
#define B64USER   "!!!B64USER!!!"
#define B64PASS   "!!!B64PASS!!!"
#define MD5USER   "!!!MD5USER!!!"
#define MD5PASS   "!!!MD5PASS!!!"
#define RAWIPAD   "!!!RAWIPAD!!!"
#define RAWPORT   "!!!RAWPORT!!!"
#define RAWTIME   "!!!RAWTIME!!!"
#define HD5USER   "!!!HD5USER!!!"
#define HD5PASS   "!!!HD5PASS!!!"

#ifndef HTTPHANDLE
 #define HTTPHANDLE void*
#endif
   
#define NEEDUSER  1
#define NEEDPASS  2


int CheckWebformAuth(HTTPHANDLE HTTPHandle,struct _request *data, int indexpos);

#endif
