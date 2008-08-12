/*
 * libiphone.h
 * Main include of libiphone
 *
 * Copyright (c) 2008 Jonathan Beck All Rights Reserved.
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

#ifndef LIBIPHONE_H
#define LIBIPHONE_H

#ifdef __cplusplus
extern "C" {
#endif





typedef struct iPhone_s *iPhone_t;
typedef struct lockdownd_client_s *lockdownd_client_t;


void free_iPhone(iPhone_t victim);
iPhone_t get_iPhone();

int lockdownd_init(iPhone_t phone, lockdownd_client_t *control);
int lockdownd_start_service(lockdownd_client_t control, const char *service);

#ifdef __cplusplus
}
#endif

#endif

