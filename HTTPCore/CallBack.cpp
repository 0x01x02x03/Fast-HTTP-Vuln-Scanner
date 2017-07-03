/** \file CallBack.h
 * Fast HTTP Auth Scanner - HTTP Callbacks Engine.
 * This file contains functions needed to handle callbacks.
 * This functions must be called from external plugins to record or modify information related to http requests.
 * \author Andres Tarasco Acuna - http://www.tarasco.org (c) 2007 - 2008
 */
#include "CallBack.h"
#include <stdio.h>
#include <stdlib.h>



typedef struct _cb_list{
    unsigned int cbType;
    HTTP_IO_REQUEST_CALLBACK cb;   
} CB_LIST, *PCB_LIST;

static PCB_LIST CBList=    NULL;
static unsigned int CBItems=   0;

/**********************************************************************************************************************/
//! This function Registers an HTTP Callback Handler and is called from external plugins
/*!
	\param cbType CallBack Type. Valid options are CBTYPE_CLIENT_REQUEST , CBTYPE_CLIENT_RESPONSE , CBTYPE_BROWSER_REQUEST , CBTYPE_SERVER_RESPONSE. Use CBTYPE_CALLBACK_ALL to match every possible callback (including undefined ones).
    \param cb CallBack Address. This is the Address of the CallBack Function that will receive HTTP parameters.
    \return If an error is detected, 0 is returned.
	\note Registered callback functions are also responsible for handling undefined CallBack types. If a registered callback function does not know how to handle an specific callback type must ingore the data.
    For more information read the plugin development documentation.
*/
/**********************************************************************************************************************/
void RegisterHTTPCallBack(unsigned int cbType, HTTP_IO_REQUEST_CALLBACK cb)
{
	CBList=(PCB_LIST)realloc(CBList,sizeof(CB_LIST)*++CBItems);
    CBList[CBItems-1].cbType=cbType;
    CBList[CBItems-1].cb=cb;
}
/**********************************************************************************************************************/
//! This function unregisters a previously loaded Callback
/*!
	\param cbType CallBack Type. Valid options are CBTYPE_CLIENT_REQUEST , CBTYPE_CLIENT_RESPONSE , CBTYPE_BROWSER_REQUEST , CBTYPE_SERVER_RESPONSE or CBTYPE_CALLBACK_ALL to match every possible callback
    \param cb CallBack Address. This is the Address of the CallBack Function that was receiving HTTP parameters.
	\return Returns the number of removed Callbacks.
	\note Its possible to remove all Callback types against a fucntion using CBTYPE_CALLBACK_ALL.
*/
/**********************************************************************************************************************/
int  RemoveHTTPCallBack(unsigned int cbType, HTTP_IO_REQUEST_CALLBACK cb){
    unsigned int ret=0;
    for (unsigned int i=0;i<CBItems;i++)
    {
        if ( (cb==NULL) || (CBList[i].cb == cb ) )
        {
            if (CBList[i].cbType & cbType)
            {
                CBList[i].cb=NULL;
                ret++;
            }
        }
    }
    if (ret==CBItems) 
    {
        free(CBList);
        CBList=NULL;
        CBItems=0;
    }
    return(ret);
}
/**********************************************************************************************************************/
//! CallBack Dispatcher. This function is called from the HTTPCore Module ( SendRawHttpRequest() ) and will send http information against registered callbacks
/*!
	\param cbType CallBack Source Type. Valid options are CBTYPE_CLIENT_REQUEST , CBTYPE_CLIENT_RESPONSE , CBTYPE_BROWSER_REQUEST , CBTYPE_SERVER_RESPONSE
	\param HTTPHandle HTTP Connection Handle with information about remote target (like ip address, port, ssl, protocol version,...)
	\param request struct containing all information related to the HTTP Request.
	\param response struct containing information about http reponse. This parameter could be NULL if the callback type is CBTYPE_CLIENT_REQUEST or CBTYPE_CLIENT_RESPONSE because request was not send yet.
	\return the return value CBRET_STATUS_NEXT_CB_CONTINUE indicates that the request (modified or not) its ok. If a registered handler blocks the request then CBRET_STATUS_CANCEL_REQUEST is returned. This value indicates that the response is locked
    \note a Blocked PHTTP_DATA request or response can be used for example when implementing an ADS filtering.
*/
/**********************************************************************************************************************/
int DoCallBack(int cbType,HTTPHANDLE HTTPHandle,PHTTP_DATA *request,PHTTP_DATA *response)
{
    unsigned int i;
    int ret;
    for (i=0; i<CBItems;i++)
    {
        if ( (CBList[i].cbType & cbType) && (CBList[i].cb) )
        {
            ret=CBList[i].cb (
                cbType,
                HTTPHandle,
				request,
				response);
            if (ret & CBRET_STATUS_NEXT_CB_BLOCK)
                break;
            if (ret & CBRET_STATUS_CANCEL_REQUEST)
            {
                return(CBRET_STATUS_CANCEL_REQUEST);
            }
        }
    }     
    return( CBRET_STATUS_NEXT_CB_CONTINUE );
}
/**********************************************************************************************************************/
