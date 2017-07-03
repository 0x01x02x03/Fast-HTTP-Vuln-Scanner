#ifndef ESTRUCTURAS_H
#define ESTRUCTURAS_H

#include <stdio.h>

struct _ports {
   int port;
   int ssl;
};

//hosts que no procesaremos
struct  _ignore {
   int status;
   char server[200];
};

//Autenticacion de routers fuera del directorio raiz
struct _fakeauth {
   unsigned int	 status;
   char  server[200];
   char  authurl[200];
   char  method[10]; //GET |POST
   char  postdata[200];
};
typedef struct _logins {
	char user[40];
} USERLOGIN;

//resultado de una peticion http


typedef struct _UserPass{
   char UserName[50];
   char Password[50];
} USERLIST;
//
//char *GetHeaderValue(struct _request *data, char  *Header) ;
///char *GetValue(const char *lpBuffer);

//información de un router que soporta auth por webform
struct _webform {
   char  model[200];       //Fake version
   unsigned int status;            //codigo de error de la página principal
   char  server[200]; //banner del servidor Web
   char  matchstring[200]; //string de la peticion con la que machear los resultados.
   char  ValidateImage[200];
   char  authurl[200];
   char  authmethod[10];
   char  authform[1024];
   int   requireloginandpass;
   char  validauthstring[200];
   char  validauthstringalt[200];
   char  invalidauthstring[200];
   char  invalidauthstringalt[200]; 
   char  AdditionalHeader[200];
   int   UpdateCookie;
   char  InitialCookieURL[200];
   char  ValidateAlternativeurl[200];
   char LoadAdditionalUrl[200];
   char ReconnectOnMatch[200];
};

//vulnerability list

typedef struct _vulnerability_match
{
   char Validatestring[200][200];
   char Ignorestring[200];
   char description[200];
   int  nstrings;
   }MATCH, *PMATCH;

typedef struct _vulnerability_list {
   char  vulnerability[200];
   unsigned int status;
   char server[200];
   char  url[200];
   char Ignoresignature[200];

   int nMatch;
   PMATCH Match;
   
} VLIST, *PVLIST;

#endif
