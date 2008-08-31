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

xmlNode *add_key_dict_node(xmlDocPtr plist, xmlNode * dict, const char *key, const char *value, int depth);
xmlNode *add_key_str_dict_element(xmlDocPtr plist, xmlNode * dict, const char *key, const char *value, int depth);
xmlNode *add_key_data_dict_element(xmlDocPtr plist, xmlNode * dict, const char *key, const char *value, int depth);
xmlNode *add_child_to_plist(xmlDocPtr plist, const char *name, const char *content, xmlNode * to_node, int depth);

void free_plist(xmlDocPtr plist);
xmlDocPtr new_plist();

char **read_dict_element_strings(xmlNode * dict);
void free_dictionary(char **dictionary);

/* Binary plist stuff */

enum {
	BPLIST_TRUE = 0x08,
	BPLIST_FALSE = 0x09,
	BPLIST_FILL = 0x0F, /* will be used for length grabbing */
	BPLIST_INT = 0x10,
	BPLIST_REAL = 0x20,
	BPLIST_DATE = 0x33,
	BPLIST_DATA = 0x40,
	BPLIST_STRING = 0x50,
	BPLIST_UNICODE = 0x60,
	BPLIST_UID = 0x70,
	BPLIST_ARRAY = 0xA0,
	BPLIST_SET = 0xC0,
	BPLIST_DICT = 0xD0,
	BPLIST_MASK = 0xF0
};

typedef struct _bplist_node {
	struct _bplist_node *next, **subnodes; // subnodes is for arrays, dicts and (potentially) sets. 
	uint64_t length, intval64;
	uint32_t intval32; // length = subnodes 
	uint16_t intval16;
	uint8_t intval8;
	uint8_t type, *indexes; // indexes for array-types; essentially specify the order in which to access for key => value pairs
	char *strval;
	double realval;
	wchar_t *unicodeval;
} bplist_node;

#endif
