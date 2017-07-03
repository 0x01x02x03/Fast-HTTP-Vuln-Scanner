#ifndef __BASE64_H
#define __BASE64_H

#include <ctype.h>
#include <stdio.h>
#include <assert.h> //for assert()

#ifdef __WIN32__RELEASE__
#include <windows.h>
#else
 #ifndef DWORD
   #define DWORD int
 #endif
#endif

unsigned int Base64EncodeGetLength( unsigned long size );
unsigned int Base64DecodeGetLength( unsigned long size );
int Base64Encode( unsigned char* out, const unsigned char* in, int inlen );
int Base64Decode( char* out, const char* in, unsigned long size );


#endif
