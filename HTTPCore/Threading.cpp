/** \file HTTP.cpp
 * Fast HTTP Auth Scanner -  Threading functions for the HTTP Core
 */

#include "Build.h"
#include "Threading.h"

#include <stdio.h>
#include <string.h>
#ifdef __WIN32__RELEASE__
 #include <windows.h>
#else
 #include <unistd.h>
 #include <pthread.h>  //pthread
#endif

/******************************************************************************/
//! This function locks a mutex/critical Section object initialized by InitMutex().
/*!
	\param mutex pointer to a pthread_mutex_t under linux or to a Critical_Section under win32.
	\note This function works under win32 and linux.
*/
/******************************************************************************/

void LockMutex(void *mutex)
{
if (mutex) {
	

#ifdef __WIN32__RELEASE__
   EnterCriticalSection((CRITICAL_SECTION*)mutex);
#else
   pthread_mutex_lock ((pthread_mutex_t*)mutex);
#endif
}
}
/******************************************************************************/
//! This function unlocks a mutex/critical Section object.
/*!
	\param mutex pointer to a pthread_mutex_t under linux or to a Critical_Section under win32.
	\note This function works under win32 and linux.
*/
/******************************************************************************/
void UnLockMutex(void *mutex)
{
if (mutex) {
	

#ifdef __WIN32__RELEASE__
   LeaveCriticalSection((CRITICAL_SECTION*)mutex);
#else
   pthread_mutex_unlock ((pthread_mutex_t*)mutex);
#endif
	}
}
/******************************************************************************/
//! This function Initializes a mutex/critical Section object.
/*!
	\param mutex pointer to a pthread_mutex_t under linux or to a Critical_Section under win32.
	\note This function works under win32 and linux.
*/
/******************************************************************************/
void InitMutex(void *mutex)
{
#ifdef __WIN32__RELEASE__
   InitializeCriticalSection((CRITICAL_SECTION*)mutex);
#else
   pthread_mutexattr_t mutexattr;
   pthread_mutexattr_settype(&mutexattr,PTHREAD_MUTEX_RECURSIVE); // Set the mutex as recursive
   pthread_mutex_init((pthread_mutex_t*)mutex, &mutexattr);  // create the mutex with the attributes set
   pthread_mutexattr_destroy(&mutexattr);
#endif
}
/******************************************************************************/
//! This function deletes a previously initialized mutex/critical Section object.
/*!
	\param mutex pointer to a pthread_mutex_t under linux or to a Critical_Section under win32.
	\note This function works under win32 and linux.
*/
/******************************************************************************/
void DeleteMutex(void *mutex)
{
#ifdef __WIN32__RELEASE__
DeleteCriticalSection((CRITICAL_SECTION*)mutex);
#else
pthread_mutex_destroy ((pthread_mutex_t*)mutex);
#endif

}

/******************************************************************************/

