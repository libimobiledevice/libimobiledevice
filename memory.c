/*
* idevice.c
* Memory management utility functions.
*
*/

#include <stdlib.h>

/**
* Frees memory allocated in libimobiledevice (using malloc).
*
* @param p The memory to free
*/
void libimobiledevice_free(void * p)
{
	free(p);
}