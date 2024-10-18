

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 06:14:07 2038
 */
/* Compiler settings for interface.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0628 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __interface_h_h__
#define __interface_h_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef DECLSPEC_XFGVIRT
#if defined(_CONTROL_FLOW_GUARD_XFG)
#define DECLSPEC_XFGVIRT(base, func) __declspec(xfg_virtual(base, func))
#else
#define DECLSPEC_XFGVIRT(base, func)
#endif
#endif

/* Forward Declarations */ 

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __Interface_INTERFACE_DEFINED__
#define __Interface_INTERFACE_DEFINED__

/* interface Interface */
/* [version][uuid] */ 

unsigned int FileSize( 
    /* [in] */ handle_t handle,
    /* [string][in] */ const unsigned char *path);

int Remove( 
    /* [in] */ handle_t handle,
    /* [string][in] */ const unsigned char *path);

int Authenticate( 
    /* [in] */ handle_t handle,
    /* [string][in] */ unsigned char *username,
    /* [string][in] */ unsigned char *password);

int Download( 
    /* [in] */ handle_t handle,
    /* [string][in] */ const unsigned char *source_path,
    /* [size_is][out][in] */ unsigned char *data,
    /* [in] */ unsigned int size);

int Upload( 
    /* [in] */ handle_t handle,
    /* [string][in] */ const unsigned char *source_path,
    /* [size_is][in] */ const unsigned char *data,
    /* [in] */ unsigned int size);

typedef /* [public][public] */ struct __MIDL_Interface_0001
    {
    boolean antivirus;
    boolean firewall;
    boolean autoupdate;
    boolean antispyware;
    boolean internetSettings;
    boolean uac;
    boolean service;
    boolean all;
    } 	SecurityStatus;

int SecurityData( 
    /* [in] */ handle_t handle,
    /* [out] */ SecurityStatus *status);

void Exit( 
    /* [in] */ handle_t IDL_handle);



extern RPC_IF_HANDLE Interface_v1_0_c_ifspec;
extern RPC_IF_HANDLE Interface_v1_0_s_ifspec;
#endif /* __Interface_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


