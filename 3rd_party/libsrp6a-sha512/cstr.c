#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "cstr.h"

#define EXPFACTOR	2		/* Minimum expansion factor */
#define MINSIZE		4		/* Absolute minimum - one word */

static char cstr_empty_string[] = { '\0' };

_TYPE( cstr * )
cstr_new()
{
  cstr * str;

  str = (cstr *) malloc(sizeof(cstr));
  if(str) {
    str->data = cstr_empty_string;
    str->length = str->cap = 0;
    str->ref = 1;
  }
  return str;
}

_TYPE( cstr * )
cstr_dup(const cstr * str)
{
  cstr * nstr = cstr_new();
  if(nstr)
    cstr_setn(nstr, str->data, str->length);
  return nstr;
}

_TYPE( cstr * )
cstr_create(const char * s)
{
  return cstr_createn(s, strlen(s));
}

_TYPE( cstr * )
cstr_createn(const char * s, int len)
{
  cstr * str = cstr_new();
  if(str) {
    cstr_setn(str, s, len);
  }
  return str;
}

_TYPE( void )
cstr_use(cstr * str)
{
  ++str->ref;
}

_TYPE( void )
cstr_clear_free(cstr * str)
{
  if(--str->ref == 0) {
    if(str->cap > 0) {
      memset(str->data, 0, str->cap);
      free(str->data);
    }
    free(str);
  }
}

_TYPE( void )
cstr_free(cstr * str)
{
  if(--str->ref == 0) {
    if(str->cap > 0)
      free(str->data);
    free(str);
  }
}

_TYPE( void )
cstr_empty(cstr * str)
{
  if(str->cap > 0)
    free(str->data);
  str->data = cstr_empty_string;
  str->length = str->cap = 0;
}

static int
cstr_alloc(cstr * str, int len)
{
  char * t;

  if(len > str->cap) {
    if(len < EXPFACTOR * str->cap)
      len = EXPFACTOR * str->cap;
    if(len < MINSIZE)
      len = MINSIZE;

    t = (char *) malloc(len * sizeof(char));
    if(t) {
      if(str->data) {
	t[str->length] = 0;
	if(str->cap > 0) {
	  if(str->length > 0)
	    memcpy(t, str->data, str->length);
	  free(str->data);
	}
      }
      str->data = t;
      str->cap = len;
      return 1;
    }
    else
      return -1;
  }
  else
    return 0;
}

_TYPE( int )
cstr_copy(cstr * dst, const cstr * src)
{
  return cstr_setn(dst, src->data, src->length);
}

_TYPE( int )
cstr_set(cstr * str, const char * s)
{
  return cstr_setn(str, s, strlen(s));
}

_TYPE( int )
cstr_setn(cstr * str, const char * s, int len)
{
  if(cstr_alloc(str, len + 1) < 0)
    return -1;
  str->data[len] = 0;
  if(s != NULL && len > 0)
    memmove(str->data, s, len);
  str->length = len;
  return 1;
}

_TYPE( int )
cstr_set_length(cstr * str, int len)
{
  if(len < str->length) {
    str->data[len] = 0;
    str->length = len;
    return 1;
  }
  else if(len > str->length) {
    if(cstr_alloc(str, len + 1) < 0)
      return -1;
    memset(str->data + str->length, 0, len - str->length + 1);
    str->length = len;
    return 1;
  }
  else
    return 0;
}

_TYPE( int )
cstr_append(cstr * str, const char * s)
{
  return cstr_appendn(str, s, strlen(s));
}

_TYPE( int )
cstr_appendn(cstr * str, const char * s, int len)
{
  if(cstr_alloc(str, str->length + len + 1) < 0)
    return -1;
  memcpy(str->data + str->length, s, len);
  str->length += len;
  str->data[str->length] = 0;
  return 1;
}

_TYPE( int )
cstr_append_str(cstr * dst, const cstr * src)
{
  return cstr_appendn(dst, src->data, src->length);
}
