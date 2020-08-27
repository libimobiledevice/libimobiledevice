/*
 * thread.h
 *
 * Copyright (c) 2012-2019 Nikias Bassen, All Rights Reserved.
 * Copyright (c) 2012 Martin Szulecki, All Rights Reserved.
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

#ifndef __THREAD_H
#define __THREAD_H

#include <stddef.h>

#ifdef WIN32
#include <windows.h>
typedef HANDLE THREAD_T;
typedef CRITICAL_SECTION mutex_t;
typedef volatile struct {
	LONG lock;
	int state;
} thread_once_t;
#define THREAD_ONCE_INIT {0, 0}
#define THREAD_ID GetCurrentThreadId()
#define THREAD_T_NULL (THREAD_T)NULL
#else
#include <pthread.h>
#include <signal.h>
typedef pthread_t THREAD_T;
typedef pthread_mutex_t mutex_t;
typedef pthread_once_t thread_once_t;
#define THREAD_ONCE_INIT PTHREAD_ONCE_INIT
#define THREAD_ID pthread_self()
#define THREAD_T_NULL (THREAD_T)NULL
#endif

typedef void* (*thread_func_t)(void* data);

int thread_new(THREAD_T* thread, thread_func_t thread_func, void* data);
void thread_detach(THREAD_T thread);
void thread_free(THREAD_T thread);
int thread_join(THREAD_T thread);
int thread_alive(THREAD_T thread);

int thread_cancel(THREAD_T thread);

#ifdef WIN32
#undef HAVE_THREAD_CLEANUP
#else
#ifdef HAVE_PTHREAD_CANCEL
#define HAVE_THREAD_CLEANUP 1
#define thread_cleanup_push(routine, arg) pthread_cleanup_push(routine, arg)
#define thread_cleanup_pop(execute) pthread_cleanup_pop(execute)
#endif
#endif

void mutex_init(mutex_t* mutex);
void mutex_destroy(mutex_t* mutex);
void mutex_lock(mutex_t* mutex);
void mutex_unlock(mutex_t* mutex);

void thread_once(thread_once_t *once_control, void (*init_routine)(void));

#endif
