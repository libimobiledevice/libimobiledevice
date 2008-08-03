/*
 * userpref.h
 * contains methods to access user specific certificates IDs and more.
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

#ifndef USERPREF_H
#define USERPREF_H

/**
* \fn char* get_host_id() 
*  method to get user's HostID. Caller must free returned buffer.
* \return the HostID if exist in config file. Returns NULL otherwise.
*/
char* get_host_id();

/**
* \fn int is_device_known(char* public_key)
*  determine if we already paired this device.
* \return 1 if device is already paired. Returns 0 otherwise.
*/
int is_device_known(char* public_key);

/**
* \fn int store_device_public_key(char* public_key)
* \return 1 if everything went well. Returns 0 otherwise.
*/
int store_device_public_key(char* public_key);

/**
* \fn char* get_root_private_key()
* \return RootPrivateKey if exists. Returns NULL otherwise.
*/
char* get_root_private_key();

/**
* \fn char* get_host_private_key()
* \return HostPrivateKey if exists. Returns NULL otherwise.
*/
char* get_host_private_key();

/**
* \fn char* get_root_certificate()
* \return RootCertificate if exists. Returns NULL otherwise.
*/
char* get_root_certificate();

/**
* \fn char* get_host_certificate()
* \return HostCertificate if exists. Returns NULL otherwise.
*/
char* get_host_certificate();

/**
* \fn int init_config_file(char* host_id, char* root_private_key, char* host_private_key, char* root_cert, char* host_cert)
* setup a brand new config file.
* \return 1 if everything went well. Returns 0 otherwise.
*/
int init_config_file(char* host_id, char* root_private_key, char* host_private_key, char* root_cert, char* host_cert);
#endif

