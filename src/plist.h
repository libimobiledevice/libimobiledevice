/*
 * plist.h
 * contains structures and the like for plists
 *
 * Copyright (c) 2008 Zach C. All Rights Reserved.
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

#ifndef PLIST_H
#define PLIST_H

#include <stdint.h>
#include <wchar.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>


typedef enum {
	PLIST_BOOLEAN,
	PLIST_UINT,
	PLIST_REAL,
	PLIST_STRING,
	PLIST_UNICODE,
	PLIST_ARRAY,
	PLIST_DICT,
	PLIST_DATE,
	PLIST_DATA,
	PLIST_KEY,
	PLIST_NONE
} plist_type;


struct plist_data {
	union {
		char boolval;
		uint64_t intval;
		double realval;
		char *strval;
		wchar_t *unicodeval;
		char *buff;
	};
	uint64_t length;
	plist_type type;
};



typedef GNode *plist_t;


void plist_new_dict(plist_t * plist);
void plist_new_array(plist_t * plist);
void plist_new_dict_in_plist(plist_t plist, plist_t * dict);
void plist_add_dict_element(plist_t dict, char *key, plist_type type, void *value, uint64_t length);
void plist_free(plist_t plist);

void plist_to_xml(plist_t plist, char **plist_xml, uint32_t * length);
void plist_to_bin(plist_t plist, char **plist_bin, uint32_t * length);

void xml_to_plist(const char *plist_xml, uint32_t length, plist_t * plist);
void bin_to_plist(const char *plist_bin, uint32_t length, plist_t * plist);

plist_t find_query_node(plist_t plist, char *key, char *request);
plist_t find_node(plist_t plist, plist_type type, void *value);
void get_type_and_value(plist_t node, plist_type * type, void *value, uint64_t * length);

#endif
