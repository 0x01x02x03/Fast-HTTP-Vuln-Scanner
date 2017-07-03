#ifndef __ROUTERAUTH_H
#define __ROUTERAUTH_H




struct _request *CheckRouterAuth(HTTPHANDLE HTTPHandle,struct _request *data,int nRouterAuth, struct _fakeauth *AuthData,int nUsers, USERLIST *userpass);

#endif
