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

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <stdint.h>
#include <wchar.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>

char *format_string(const char *buf, int cols, int depth);
xmlNode *add_key_dict_node(xmlDocPtr plist, xmlNode * dict, const char *key, const char *value, int depth);
xmlNode *add_key_str_dict_element(xmlDocPtr plist, xmlNode * dict, const char *key, const char *value, int depth);
xmlNode *add_key_data_dict_element(xmlDocPtr plist, xmlNode * dict, const char *key, const char *value, int depth);
xmlNode *add_child_to_plist(xmlDocPtr plist, const char *name, const char *content, xmlNode * to_node, int depth);

void free_plist(xmlDocPtr plist);
xmlDocPtr new_plist();

char **read_dict_element_strings(xmlNode * dict);
void free_dictionary(char **dictionary);

/* Binary plist stuff */


typedef enum {
	PLIST_BOOLEAN,
	PLIST_UINT8,
	PLIST_UINT16,
	PLIST_UINT32,
	PLIST_UINT64,
	PLIST_FLOAT32,
	PLIST_FLOAT64,
	PLIST_STRING,
	PLIST_UNICODE,
	PLIST_ARRAY,
	PLIST_DICT,
	PLIST_DATE,
	PLIST_DATA,
	PLIST_PLIST,
	PLIST_KEY,
} plist_type;


typedef GNode *plist_t;
typedef GNode *dict_t;
typedef GNode *array_t;


void plist_new_plist(plist_t * plist);
void plist_new_dict_in_plist(plist_t plist, dict_t * dict);
void plist_new_array_in_plist(plist_t plist, int length, plist_type type, void **values, array_t * array);
void plist_add_dict_element(dict_t dict, char *key, plist_type type, void *value);
void plist_free(plist_t plist);

void plist_to_xml(plist_t plist, char **plist_xml, uint32_t * length);
void plist_to_bin(plist_t plist, char **plist_bin, uint32_t * length);

void xml_to_plist(const char *plist_xml, uint32_t length, plist_t * plist);
void bin_to_plist(const char *plist_bin, uint32_t length, plist_t * plist);

GNode *find_query_node(plist_t plist, char *key, char *request);
void get_type_and_value(GNode * node, plist_type * type, void *value);
#endif
