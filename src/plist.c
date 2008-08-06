/*
 * plist.c
 * Builds plist XML structures.
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

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>
#include "plist.h"

const char *plist_base = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
</plist>\0";

char* format_string(char* buf, int cols, int depth)
{
	int colw = depth + cols + 1; //new buf cols width
	int len = strlen(buf);
	//int nlines = ceil((float)len / (float)cols);
	int nlines = len / cols + 1;
 	char* new_buf = (char*)malloc(nlines * colw + depth + 1);
	int i = 0;
	int j = 0;
	for (i = 0; i < nlines; i++){
		new_buf[i * colw] = '\n';
		for (j = 0; j < depth; j++)
			new_buf[i * colw + 1 + j] = '\t';
		memcpy(new_buf + i * colw + 1 + depth, buf + i * cols, cols);
	}
	new_buf[len+(1+depth)*nlines] = '\n';
	for (j = 0; j < depth; j++)
		new_buf[len+(1+depth)*nlines + 1 + j] = '\t';
	new_buf[len+(1+depth)*nlines+depth+1] = '\0';
	free(buf);
	return new_buf;
}

xmlDocPtr new_plist() {
	char *plist = strdup(plist_base);
	xmlDocPtr plist_xml = xmlReadMemory(plist, strlen(plist), NULL, NULL, 0);
	if (!plist_xml) return NULL;
	free(plist);
	return plist_xml;
}

void free_plist(xmlDocPtr plist) {
	if (!plist) return;
	xmlFreeDoc(plist);
}

xmlNode *add_child_to_plist(xmlDocPtr plist, const char *name, const char *content, xmlNode *to_node, int depth) {
	if (!plist) return NULL;
	int i = 0;
	xmlNode *child;
	if (!to_node) to_node = xmlDocGetRootElement(plist);
	for (i = 0; i < depth; i++) {
		xmlNodeAddContent(to_node, "\t");
	}
	child = xmlNewChild(to_node, NULL, name, content);
	xmlNodeAddContent(to_node, "\n");
	return child;
}

xmlNode *add_key_str_dict_element(xmlDocPtr plist, xmlNode *dict, const char *key, const char *value, int depth) {
	xmlNode *keyPtr;
	keyPtr = add_child_to_plist(plist, "key", key, dict, depth);
	add_child_to_plist(plist, "string", value, dict, depth);
	return keyPtr;
}

xmlNode *add_key_dict_node(xmlDocPtr plist, xmlNode *dict, const char *key, const char *value, int depth) {
	xmlNode *child;
	add_child_to_plist(plist, "key", key, dict, depth);
	child = add_child_to_plist(plist, "dict", value, dict, depth);
	return child;
}

xmlNode *add_key_data_dict_element(xmlDocPtr plist, xmlNode *dict, const char *key, const char *value, int depth) {
	xmlNode *keyPtr;
	keyPtr = add_child_to_plist(plist, "key", key, dict, depth);
	add_child_to_plist(plist, "data", format_string(value, 60, depth), dict, depth);
	return keyPtr;
}

char **read_dict_element_strings(xmlNode *dict) {
	// reads a set of keys and strings into an array where each even number is a key and odd numbers are values.
	// if the odd number is \0, that's the end of the list. 
	char **return_me = NULL, **old = NULL;
	int current_length = 0;
	int current_pos = 0;
	xmlNode *dict_walker;
	
	for (dict_walker = dict->children; dict_walker; dict_walker = dict_walker->next) {
		if (!xmlStrcmp(dict_walker->name, "key")) {
			current_length += 2;
			old = return_me;
			return_me = realloc(return_me, sizeof(char*) * current_length);
			if (!return_me) {
				free(old);
				return NULL;
			}
			return_me[current_pos++] = xmlNodeGetContent(dict_walker);
			return_me[current_pos++] = xmlNodeGetContent(dict_walker->next->next);
		}
	}
	
	// one last thing...
	old = return_me;
	return_me = realloc(return_me, sizeof(char*) * (current_length+1));
	return_me[current_pos] = strdup("");
	
	return return_me;
}

void free_dictionary(char **dictionary) {
	if (!dictionary) return;
	int i = 0;
	
	for (i = 0; strcmp(dictionary[i], ""); i++) {
		free(dictionary[i]);
	}
	
	free(dictionary[i]);
	free(dictionary);
}

