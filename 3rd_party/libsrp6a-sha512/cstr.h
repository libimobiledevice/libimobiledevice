#ifndef _CSTR_H_
#define _CSTR_H_

/* A general-purpose string "class" for C */

#if     !defined(P)
#ifdef  __STDC__
#define P(x)    x
#else
#define P(x)    ()
#endif
#endif

/*	For building dynamic link libraries under windows, windows NT 
 *	using MSVC1.5 or MSVC2.0
 */

#ifndef _DLLDECL
#define _DLLDECL

#ifdef MSVC15	/* MSVC1.5 support for 16 bit apps */
#define _MSVC15EXPORT _export
#define _MSVC20EXPORT
#define _DLLAPI _export _pascal
#define _CDECL
#define _TYPE(a) a _MSVC15EXPORT
#define DLLEXPORT 1

#elif defined(MSVC20) || (defined(_USRDLL) && defined(SRP_EXPORTS))
#define _MSVC15EXPORT
#define _MSVC20EXPORT _declspec(dllexport)
#define _DLLAPI
#define _CDECL
#define _TYPE(a) _MSVC20EXPORT a
#define DLLEXPORT 1

#else			/* Default, non-dll.  Use this for Unix or DOS */
#define _MSVC15DEXPORT
#define _MSVC20EXPORT
#define _DLLAPI
#if defined(WINDOWS) || defined(_WIN32)
#define _CDECL _cdecl
#else
#define _CDECL
#endif
#define _TYPE(a) a _CDECL
#endif
#endif /* _DLLDECL */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct cstr_st {
  char * data;	/* Okay to access data and length fields directly */
  int length;
  int cap;
  int ref;	/* Simple reference counter */
} cstr;

_TYPE( cstr * ) cstr_new P((void));
_TYPE( cstr * ) cstr_dup P((const cstr * str));
_TYPE( cstr * ) cstr_create P((const char * s));
_TYPE( cstr * ) cstr_createn P((const char * s, int len));

_TYPE( void ) cstr_free P((cstr * str));
_TYPE( void ) cstr_clear_free P((cstr * str));
_TYPE( void ) cstr_use P((cstr * str));
_TYPE( void ) cstr_empty P((cstr * str));
_TYPE( int ) cstr_copy P((cstr * dst, const cstr * src));
_TYPE( int ) cstr_set P((cstr * str, const char * s));
_TYPE( int ) cstr_setn P((cstr * str, const char * s, int len));
_TYPE( int ) cstr_set_length P((cstr * str, int len));
_TYPE( int ) cstr_append P((cstr * str, const char * s));
_TYPE( int ) cstr_appendn P((cstr * str, const char * s, int len));
_TYPE( int ) cstr_append_str P((cstr * dst, const cstr * src));

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _CSTR_H_ */
