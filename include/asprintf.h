#ifndef __ASPRINTF_H
#define __ASPRINTF_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef HAVE_VASPRINTF
#ifdef _MSC_VER
static __inline int vasprintf(char **PTR, const char *TEMPLATE, va_list AP)
#else
static inline int vasprintf(char **PTR, const char *TEMPLATE, va_list AP)
#endif
{
	int res;
	char buf[16];
	res = vsnprintf(buf, 16, TEMPLATE, AP);
	if (res > 0) {
		*PTR = (char*)malloc(res+1);
		res = vsnprintf(*PTR, res+1, TEMPLATE, AP);
	}
	return res;
}
#endif

#ifndef HAVE_ASPRINTF
#ifdef _MSC_VER
static __inline int asprintf(char **PTR, const char *TEMPLATE, ...)
#else
static inline int asprintf(char **PTR, const char *TEMPLATE, ...)
#endif
{
	int res;
	va_list AP;
	va_start(AP, TEMPLATE);
	res = vasprintf(PTR, TEMPLATE, AP);
	va_end(AP);
	return res;
}
#endif

#endif /* ASPRINTF_H */
