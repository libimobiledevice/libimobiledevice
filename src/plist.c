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
#include <assert.h>
#include "plist.h"

const char *plist_base = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
</plist>\0";

/** Formats a block of text to be a given indentation and width.
 * 
 * The total width of the return string will be depth + cols.
 *
 * @param buf The string to format.
 * @param cols The number of text columns for returned block of text.
 * @param depth The number of tabs to indent the returned block of text.
 *
 * @return The formatted string.
 */
char *format_string(const char *buf, int cols, int depth)
{
	int colw = depth + cols + 1;
	int len = strlen(buf);
	int nlines = len / cols + 1;
	char *new_buf = (char *) malloc(nlines * colw + depth + 1);
	int i = 0;
	int j = 0;

	assert(cols >= 0);
	assert(depth >= 0);

	// Inserts new lines and tabs at appropriate locations
	for (i = 0; i < nlines; i++) {
		new_buf[i * colw] = '\n';
		for (j = 0; j < depth; j++)
			new_buf[i * colw + 1 + j] = '\t';
		memcpy(new_buf + i * colw + 1 + depth, buf + i * cols, cols);
	}
	new_buf[len + (1 + depth) * nlines] = '\n';

	// Inserts final row of indentation and termination character
	for (j = 0; j < depth; j++)
		new_buf[len + (1 + depth) * nlines + 1 + j] = '\t';
	new_buf[len + (1 + depth) * nlines + depth + 1] = '\0';

	return new_buf;
}

/** Creates a new plist XML document.
 * 
 * @return The plist XML document.
 */
xmlDocPtr new_plist()
{
	char *plist = strdup(plist_base);
	xmlDocPtr plist_xml = xmlReadMemory(plist, strlen(plist), NULL, NULL, 0);

	if (!plist_xml)
		return NULL;

	free(plist);

	return plist_xml;
}

/** Destroys a previously created XML document.
 *
 * @param plist The XML document to destroy.
 */
void free_plist(xmlDocPtr plist)
{
	if (!plist)
		return;

	xmlFreeDoc(plist);
}

/** Adds a new node as a child to a given node.
 *
 * This is a lower level function so you probably want to use
 * add_key_str_dict_element, add_key_dict_node or add_key_data_dict_element
 * instead.
 *  
 * @param plist The plist XML document to which the to_node belongs.
 * @param name The name of the new node.
 * @param content The string containing the text node of the new node.
 * @param to_node The node to attach the child node to. If none is given, the
 * 		  root node of the given document is used.
 * @param depth The number of tabs to indent the new node.
 *
 * @return The newly created node.
 */
xmlNode *add_child_to_plist(xmlDocPtr plist, const char *name, const char *content, xmlNode * to_node, int depth)
{
	int i = 0;
	xmlNode *child;

	if (!plist)
		return NULL;
	assert(depth >= 0);
	if (!to_node)
		to_node = xmlDocGetRootElement(plist);

	for (i = 0; i < depth; i++) {
		xmlNodeAddContent(to_node, "\t");
	}
	child = xmlNewChild(to_node, NULL, name, content);
	xmlNodeAddContent(to_node, "\n");

	return child;
}

/** Adds a string key-pair to a plist XML document.
 * 
 * @param plist The plist XML document to add the new node to.
 * @param dict The dictionary node within the plist XML document to add the new node to.
 * @param key The string containing the key value.
 * @param value The string containing the value.
 * @param depth The number of tabs to indent the new node.
 *
 * @return The newly created key node.
 */
xmlNode *add_key_str_dict_element(xmlDocPtr plist, xmlNode * dict, const char *key, const char *value, int depth)
{
	xmlNode *keyPtr;

	keyPtr = add_child_to_plist(plist, "key", key, dict, depth);
	add_child_to_plist(plist, "string", value, dict, depth);

	return keyPtr;
}

/** Adds a new dictionary key-pair to a plist XML document.
 * 
 * @param plist The plist XML document to add the new node to.
 * @param dict The dictionary node within the plist XML document to add the new node to.
 * @param key The string containing the key value.
 * @param value The string containing the value.
 * @param depth The number of tabs to indent the new node.
 *
 * @return The newly created dict node.
 */
xmlNode *add_key_dict_node(xmlDocPtr plist, xmlNode * dict, const char *key, const char *value, int depth)
{
	xmlNode *child;

	add_child_to_plist(plist, "key", key, dict, depth);
	child = add_child_to_plist(plist, "dict", value, dict, depth);

	return child;
}

/** Adds a new data dictionary key-pair to a plist XML document.
 * 
 * @param plist The plist XML document to add the new node to.
 * @param dict The dictionary node within the plist XML document to add the new node to.
 * @param key The string containing the key value.
 * @param value The string containing the value.
 * @param depth The number of tabs to indent the new node.
 *
 * @return The newly created key node.
 */
xmlNode *add_key_data_dict_element(xmlDocPtr plist, xmlNode * dict, const char *key, const char *value, int depth)
{
	xmlNode *keyPtr;

	keyPtr = add_child_to_plist(plist, "key", key, dict, depth);
	add_child_to_plist(plist, "data", format_string(value, 60, depth), dict, depth);

	return keyPtr;
}

/** Reads a set of keys and strings into an array from a plist XML document.
 *
 * @param dict The root XMLNode of a plist XML document to be read.
 * 
 * @return  An array where each even number is a key and the odd numbers are
 *          values.  If the odd number is \0, that's the end of the list.
 */
char **read_dict_element_strings(xmlNode * dict)
{
	char **return_me = NULL, **old = NULL;
	int current_length = 0;
	int current_pos = 0;
	xmlNode *dict_walker;

	for (dict_walker = dict->children; dict_walker; dict_walker = dict_walker->next) {
		if (!xmlStrcmp(dict_walker->name, "key")) {
			current_length += 2;
			old = return_me;
			return_me = realloc(return_me, sizeof(char *) * current_length);
			if (!return_me) {
				free(old);
				return NULL;
			}
			return_me[current_pos++] = xmlNodeGetContent(dict_walker);
			return_me[current_pos++] = xmlNodeGetContent(dict_walker->next->next);
		}
	}

	old = return_me;
	return_me = realloc(return_me, sizeof(char *) * (current_length + 1));
	return_me[current_pos] = NULL;

	return return_me;
}

/** Destroys a dictionary as returned by read_dict_element_strings
 */
void free_dictionary(char **dictionary)
{
	int i = 0;

	if (!dictionary)
		return;

	for (i = 0; dictionary[i]; i++) {
		free(dictionary[i]);
	}

	free(dictionary);
}
