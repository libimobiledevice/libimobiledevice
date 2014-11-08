#ifndef MSC_H
#define MSC_H

#ifdef _MSC_VER
#define __func__ __FUNCTION__
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif

#endif
