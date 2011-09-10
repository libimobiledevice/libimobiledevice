#ifndef ASPRINTF_H
#define ASPRINTF_H
#ifndef vasprintf
static inline int vasprintf(char **PTR, const char *TEMPLATE, va_list AP)
{
	int res;
	*PTR = (char*)malloc(512);
	res = vsnprintf(*PTR, 512, TEMPLATE, AP);
	return res;
}
#endif
#ifndef asprintf
static inline int asprintf(char **PTR, const char *TEMPLATE, ...)
{
	int res;
	va_list AP;
	va_start(AP, TEMPLATE);
	res = vasprintf(PTR, TEMPLATE, AP);
	va_end(AP);
	return res;
}
#endif
#endif
