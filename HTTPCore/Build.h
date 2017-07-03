
#ifndef __BUILD_H_
#define __BUILD_H_

/****************** GLOBAL FLAGS **********************/

#ifndef LINUX

#ifndef __WIN32__RELEASE__
#define __WIN32__RELEASE__
#endif

# if defined(_MSC_VER)
# ifndef _CRT_SECURE_NO_DEPRECATE
# define _CRT_SECURE_NO_DEPRECATE (1)
# endif
# pragma warning(disable : 4996)
# endif

#define snprintf _snprintf
#define stricmp  _stricmp
#define strnicmp _strnicmp
/*
#ifdef  _strnicmp
#define strnicmp _strnicmp
#endif



#ifndef _strdup
#define _strdup strdup
#endif
*/
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>  //pthread
#include <ctype.h> //toupper
#include <time.h>
#include <sys/timeb.h>
#include <sys/time.h> //gettimeofday
#include <sys/mman.h>  //mmap
//#include <linux/types.h> //__int64
typedef int64_t __int64;
typedef uint64_t __uint64;
#define MAXIMUM_WAIT_OBJECTS 64
#define MAX_PATH 256
#define _strdup strdup
#define BOOL int
#define closesocket close
#define strnicmp strncasecmp
#define  stricmp strcasecmp
#define ioctlsocket ioctl
#define Sleep usleep
#define CRITICAL_SECTION pthread_mutex_t
#endif
/****************** GLOBAL FLAGS **********************/

#endif


