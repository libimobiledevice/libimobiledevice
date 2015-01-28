/*
 * thread.c
 *
 * Copyright (c) 2012 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2012 Nikias Bassen All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "thread.h"

int thread_new(thread_t *thread, thread_func_t thread_func, void* data)
{
#ifdef WIN32
	HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread_func, data, 0, NULL);
	if (th == NULL) {
		return -1;
	}
	*thread = th;
	return 0;
#else
	int res = pthread_create(thread, NULL, thread_func, data);
	return res;
#endif
}

void thread_free(thread_t thread)
{
#ifdef WIN32
	CloseHandle(thread);
#endif
}

void thread_join(thread_t thread)
{
	/* wait for thread to complete */
#ifdef WIN32
	WaitForSingleObject(thread, INFINITE);
#else
	pthread_join(thread, NULL);
#endif
}

void mutex_init(mutex_t* mutex)
{
#ifdef WIN32
	InitializeCriticalSection(mutex);
#else
	pthread_mutex_init(mutex, NULL);
#endif
}

void mutex_destroy(mutex_t* mutex)
{
#ifdef WIN32
	DeleteCriticalSection(mutex);
#else
	pthread_mutex_destroy(mutex);
#endif
}

void mutex_lock(mutex_t* mutex)
{
#ifdef WIN32
	EnterCriticalSection(mutex);
#else
	pthread_mutex_lock(mutex);
#endif
}

void mutex_unlock(mutex_t* mutex)
{
#ifdef WIN32
	LeaveCriticalSection(mutex);
#else
	pthread_mutex_unlock(mutex);
#endif
}

void thread_once(thread_once_t *once_control, void (*init_routine)(void))
{
#ifdef WIN32
	while (InterlockedExchange(&(once_control->lock), 1) != 0) {
		Sleep(1);
	}
	if (!once_control->state) {
		once_control->state = 1;
		init_routine();
	}
	InterlockedExchange(&(once_control->lock), 0);
#else
	pthread_once(once_control, init_routine);
#endif
}
