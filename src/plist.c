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
#include "utils.h"
#include "plist.h"
#include <wchar.h>


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

/*
 * Binary propertylist code follows
 */


/*
 * This is how parsing a bplist is going to have to work:
 * 		- The entire binary plist is going to have to be in memory.
 * 		- A function, parse_nodes(), will have to be a recursive function
 * 		  which iterates over the binary plist and reads in elements into bplist_node structs
 * 		  and handles them accordingly. The end result should be a somewhat-hierarchical layout 
 * 		  of bplist_nodes.
 * 		- parse_nodes() will return the first node it encounters, which is usually the "root" node. 
 */

uint32_t uipow(uint32_t value, uint32_t power)
{
	if (!power)
		return 1;
	int i = 0, oVal = value;
	for (i = 1; i < power; i++) {
		value *= oVal;
	}
	return value;
}

void byte_convert(char *address, size_t size)
{
	int i = 0, j = 0;
	char tmp = '\0';

	for (i = 0; i < (size / 2); i++) {
		tmp = address[i];
		j = ((size - 1) + 0) - i;
		address[i] = address[j];
		address[j] = tmp;
	}
}



void print_bytes(char *val, size_t size)
{
	int i = 0;
	for (i = 0; i < size; i++) {
		printf("Byte %i: 0x%x\n", i, val[i]);
	}
}



struct plist_data {
	union {
		char boolval;
		uint8_t intval8;
		uint16_t intval16;
		uint32_t intval32;
		uint64_t intval64;
		float realval32;
		double realval64;
		char *strval;
		wchar_t *unicodeval;
		struct {
			char *buff;
			uint8_t ref_size;
		};
	};
	uint64_t length;
	plist_type type;
};

enum {
	BPLIST_TRUE = 0x08,
	BPLIST_FALSE = 0x09,
	BPLIST_FILL = 0x0F,			/* will be used for length grabbing */
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

void plist_new_plist(plist_t * plist)
{
	if (*plist != NULL)
		return;
	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);
	data->type = PLIST_PLIST;
	*plist = g_node_new(data);
}

void plist_new_dict_in_plist(plist_t plist, dict_t * dict)
{
	if (!plist || *dict)
		return;

	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);
	data->type = PLIST_DICT;
	*dict = g_node_new(data);
	g_node_append(plist, *dict);
}

void plist_new_array_in_plist(plist_t plist, int length, plist_type type, void **values, array_t * array)
{
}

void plist_add_dict_element(dict_t dict, char *key, plist_type type, void *value)
{
	if (!dict || !key || !value)
		return;

	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);
	data->type = PLIST_KEY;
	data->strval = strdup(key);
	GNode *keynode = g_node_new(data);
	g_node_append(dict, keynode);

	//now handle value
	struct plist_data *val = (struct plist_data *) calloc(sizeof(struct plist_data), 1);
	val->type = type;

	switch (type) {
	case PLIST_BOOLEAN:
		val->boolval = *((char *) value);
		break;
	case PLIST_UINT8:
		val->intval8 = *((uint8_t *) value);
		break;
	case PLIST_UINT16:
		val->intval16 = *((uint16_t *) value);
		break;
	case PLIST_UINT32:
		val->intval32 = *((uint32_t *) value);
		break;
	case PLIST_UINT64:
		val->intval64 = *((uint64_t *) value);
		break;
	case PLIST_FLOAT32:
		val->realval32 = *((float *) value);
		break;
	case PLIST_FLOAT64:
		val->realval64 = *((double *) value);
		break;
	case PLIST_STRING:
		val->strval = strdup((char *) value);
		break;
	case PLIST_UNICODE:
		val->unicodeval = wcsdup((wchar_t *) value);
		break;
	case PLIST_DATA:
		val->buff = strdup((char *) value);
		break;
	case PLIST_ARRAY:
	case PLIST_DICT:
	case PLIST_DATE:
	case PLIST_PLIST:
	default:
		break;
	}
	GNode *valnode = g_node_new(val);
	g_node_append(dict, valnode);
}

void plist_free(plist_t plist)
{
	g_node_destroy(plist);
}

void node_to_xml(GNode * node, gpointer data)
{
	if (!node)
		return;

	struct plist_data *node_data = (struct plist_data *) node->data;

	xmlNodePtr child_node = NULL;
	char isStruct = FALSE;

	gchar *tag = NULL;
	gchar *val = NULL;

	switch (node_data->type) {
	case PLIST_BOOLEAN:
		{
			if (node_data->boolval)
				tag = "true";
			else
				tag = "false";
		}
		break;

	case PLIST_UINT8:
		tag = "integer";
		val = g_strdup_printf("%u", node_data->intval8);
		break;

	case PLIST_UINT16:
		tag = "integer";
		val = g_strdup_printf("%u", node_data->intval16);
		break;

	case PLIST_UINT32:
		tag = "integer";
		val = g_strdup_printf("%u", node_data->intval32);
		break;

	case PLIST_UINT64:
		tag = "integer";
		val = g_strdup_printf("%lu", (long unsigned int) node_data->intval64);
		break;

	case PLIST_FLOAT32:
		tag = "real";
		val = g_strdup_printf("%f", node_data->realval32);
		break;

	case PLIST_FLOAT64:
		tag = "real";
		val = g_strdup_printf("%Lf", (long double) node_data->intval64);
		break;

	case PLIST_STRING:
		tag = "string";
		val = g_strdup(node_data->strval);
		break;

	case PLIST_UNICODE:
		tag = "string";
		val = g_strdup((gchar *) node_data->unicodeval);
		break;

	case PLIST_KEY:
		tag = "key";
		val = g_strdup((gchar *) node_data->strval);
		break;

	case PLIST_DATA:
		tag = "data";
		val = format_string(node_data->buff, 60, 0);
		break;
	case PLIST_ARRAY:
		tag = "array";
		isStruct = TRUE;
		break;
	case PLIST_DICT:
		tag = "dict";
		isStruct = TRUE;
		break;
	case PLIST_PLIST:
		tag = "plist";
		isStruct = TRUE;
		break;
	case PLIST_DATE:			//TODO : handle date tag
	default:
		break;
	}

	child_node = xmlNewChild(data, NULL, tag, val);
	xmlNodeAddContent(child_node, "\n");
	g_free(val);

	if (isStruct)
		g_node_children_foreach(node, G_TRAVERSE_ALL, node_to_xml, child_node);

	return;
}

void xml_to_node(xmlNodePtr xml_node, GNode * plist_node)
{
	xmlNodePtr node = NULL;
	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);
	GNode *subnode = g_node_new(data);
	g_node_append(plist_node, subnode);

	for (node = xml_node->children; node; node = node->next) {

		if (!xmlStrcmp(node->name, "true")) {
			data->boolval = 1;
			data->type = PLIST_BOOLEAN;
			continue;
		}

		if (!xmlStrcmp(node->name, "false")) {
			data->boolval = 0;
			data->type = PLIST_BOOLEAN;
			continue;
		}

		if (!xmlStrcmp(node->name, "integer")) {
			char *strval = xmlNodeGetContent(node);
			data->intval64 = atoi(strval);
			data->type = PLIST_UINT64;
			continue;
		}

		if (!xmlStrcmp(node->name, "real")) {
			char *strval = xmlNodeGetContent(node);
			data->realval64 = atof(strval);
			data->type = PLIST_FLOAT64;
			continue;
		}

		if (!xmlStrcmp(node->name, "date"))
			continue;			//TODO : handle date tag

		if (!xmlStrcmp(node->name, "string")) {
			data->strval = strdup(xmlNodeGetContent(node));
			data->type = PLIST_STRING;
			continue;
		}

		if (!xmlStrcmp(node->name, "key")) {
			data->strval = strdup(xmlNodeGetContent(node));
			data->type = PLIST_KEY;
			continue;
		}

		if (!xmlStrcmp(node->name, "data")) {
			data->buff = strdup(xmlNodeGetContent(node));
			data->type = PLIST_DATA;
			continue;
		}

		if (!xmlStrcmp(node->name, "array")) {
			data->type = PLIST_ARRAY;
			xml_to_node(node, subnode);
			continue;
		}

		if (!xmlStrcmp(node->name, "dict")) {
			data->type = PLIST_DICT;
			xml_to_node(node, subnode);
			continue;
		}
	}
}

void plist_to_xml(plist_t plist, char **plist_xml)
{
	if (!plist || !plist_xml || *plist_xml)
		return;
	xmlDocPtr plist_doc = new_plist();
	xmlNodePtr root_node = xmlDocGetRootElement(plist_doc);
	g_node_children_foreach(plist, G_TRAVERSE_ALL, node_to_xml, root_node);
	int size = 0;
	xmlDocDumpMemory(plist_doc, (xmlChar **) plist_xml, &size);
}

GNode *parse_raw_node(const char *bpbuffer, uint32_t bplength, uint32_t * position, uint8_t ref_size)
{
	if (!position || !bpbuffer || !bplength)
		return NULL;

	uint8_t modifier = 0;
	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);
	GNode *new_node = g_node_new(data);
	GNode *length_stupidity = NULL;

	int myPos = *position;
	if (myPos == bplength || (myPos + 1) == bplength) {
		g_node_destroy(new_node);
		return NULL;
	}							// end of string

	uint32_t length = 0;
	if (!myPos) {
		if (strncmp(bpbuffer, "bplist00", strlen("bplist00"))) {
			return NULL;		// badness!
		}
		myPos += strlen("bplist00");
	}
	// Get the node's type.
	if (bpbuffer[myPos] == BPLIST_DATE) {	// handle date separately, but do it as a real
		// better handling of date; basically interpret as real or double
		data->type = BPLIST_DATE;
		length = 8;				// always 8 for "date" (Apple intended it, not me)
		myPos++;
		memcpy(&data->realval64, bpbuffer + myPos, sizeof(data->realval64));
		byte_convert((char *) &data->realval64, sizeof(data->realval64));
		myPos += length;
		*position = myPos;
		return new_node;
	}

	int type = bpbuffer[myPos] & BPLIST_MASK;
	data->length = bpbuffer[myPos] & BPLIST_FILL;

	if (!type) {
		// what? check if it's a boolean.
		if (bpbuffer[myPos] == BPLIST_TRUE || bpbuffer[myPos] == BPLIST_FALSE) {
			// okay, so it is. Carry on.
			data->type = PLIST_BOOLEAN;
			data->boolval = TRUE;
			data->length = 0;
		} else {
			// er, what? we have a bad type here. Return NULL.
			g_node_destroy(new_node);
			//printf("parse_raw_node: lol type: type given %x\n", bpbuffer[myPos]);
			return NULL;
		}
	}

	myPos++;					// puts us in the data.
	if (length == BPLIST_FILL) {	// Data happens to contain length...
		// what? you're going to make me parse an int for the length. You suck.
		*position = myPos;
		length_stupidity = parse_raw_node(bpbuffer, bplength, &myPos, ref_size);
		switch (((struct plist_data *) length_stupidity->data)->type) {
		case PLIST_UINT8:
			data->length = ((struct plist_data *) length_stupidity->data)->intval8;
			break;
		case PLIST_UINT16:
			data->length = ((struct plist_data *) length_stupidity->data)->intval16;
			break;
		case PLIST_UINT32:
			data->length = ((struct plist_data *) length_stupidity->data)->intval32;
			break;
		case PLIST_UINT64:
			data->length = ((struct plist_data *) length_stupidity->data)->intval64;
			break;
		default:
			g_node_destroy(new_node);
			g_node_destroy(length_stupidity);
			return NULL;
		}
		// There, we have our fucking length now.
		*position = myPos;
		g_node_destroy(length_stupidity);	// cleanup
	}
	// Now we're in the data. 
	// Error-checking sorta
	if ((myPos + data->length) >= bplength) {
		data->length = bplength - myPos;	// truncate the object
	}
	// And now for the greatest show on earth: the giant fucking switch statement.
	switch (type) {
	case BPLIST_INT:
		data->length = uipow(2, data->length);	// make length less misleading
		switch (data->length) {
		case sizeof(uint8_t):
			data->type = PLIST_UINT8;
			data->intval8 = bpbuffer[myPos];
			break;
		case sizeof(uint16_t):
			data->type = PLIST_UINT16;
			memcpy(&data->intval16, bpbuffer + myPos, sizeof(uint16_t));
			data->intval16 = ntohs(data->intval16);
			break;
		case sizeof(uint32_t):
			data->type = PLIST_UINT32;
			memcpy(&data->intval32, bpbuffer + myPos, sizeof(uint32_t));
			data->intval32 = ntohl(data->intval32);
			break;
		case sizeof(uint64_t):
			data->type = PLIST_UINT64;
			memcpy(&data->intval64, bpbuffer + myPos, sizeof(uint64_t));
			byte_convert((char *) &data->intval64, sizeof(uint64_t));
			break;
		default:
			g_node_destroy(new_node);
			printf("parse_raw_node: lol: invalid int: size given %lu\n", (long unsigned int) length);
			printf("parse_raw_node: lol: by the way sizeof(uint64) = %i\n", sizeof(uint64_t));
			return NULL;
		}
		break;

	case BPLIST_REAL:
		data->length = uipow(2, data->length);
		switch (data->length) {
		case sizeof(float):
			data->type = PLIST_FLOAT32;
			memcpy(&data->realval32, bpbuffer + myPos, data->length);
			byte_convert((char *) &data->realval32, sizeof(float));	//necessary ??
			break;
		case sizeof(double):
			data->type = PLIST_FLOAT64;
			memcpy(&data->realval64, bpbuffer + myPos, data->length);
			byte_convert((char *) &data->realval64, sizeof(double));
			break;
		default:
			g_node_destroy(new_node);
			printf("parse_raw_node: lol: invalid real: size given %lu\n", (long unsigned int) length);
			printf("parse_raw_node: lol: by the way sizeof(uint64) = %i\n", sizeof(uint64_t));
			return NULL;
		}
		break;

	case BPLIST_STRING:
		data->type = PLIST_STRING;
		data->strval = (char *) malloc(sizeof(char) * data->length);
		memcpy(data->strval, bpbuffer + myPos, data->length);
		break;

	case BPLIST_UNICODE:
		data->type = PLIST_UNICODE;
		data->unicodeval = (wchar_t *) malloc(sizeof(wchar_t) * data->length);
		memcpy(data->unicodeval, bpbuffer + myPos, data->length);
		break;

	case BPLIST_DICT:			/* returning a raw dict, it forward-references, so. */
		data->length = data->length * 2;	// dicts lie
		data->type = PLIST_DICT;

	case BPLIST_ARRAY:			/* returning a raw array, it forward-references, so. */
		data->ref_size = ref_size;	// in arrays and dicts, the "ref size" alluded to in the trailer applies, and should be stored in intval8 so as to save space.
		if (data->type == 0)
			data->type = PLIST_ARRAY;
	case BPLIST_DATA:
		if (data->type == 0)
			data->type = PLIST_DATA;
	default:					/* made to hold raw data. */
		modifier = (data->ref_size > 0) ? data->ref_size : 1;
		data->buff = (char *) malloc(sizeof(char) * (data->length * modifier));
		memcpy(data->buff, bpbuffer + myPos, (data->length * modifier));
		break;

	}

	myPos += data->length;
	*position = myPos;
	return new_node;
}

plist_t parse_nodes(const char *bpbuffer, uint32_t bplength, uint32_t * position)
{
	plist_t *nodeslist = NULL, *newaddr = NULL;
	plist_t new_node = NULL, root_node = NULL;

	uint32_t nodeslength = 0;
	uint8_t offset_size = 0, dict_param_size = 0;
	offset_size = bpbuffer[bplength - 26];
	dict_param_size = bpbuffer[bplength - 25];
	uint64_t current_offset = 0;
	uint64_t num_objects = 0, root_object = 0, offset_table_index = 0;
	memcpy(&num_objects, bpbuffer + bplength - 24, sizeof(uint64_t));
	memcpy(&root_object, bpbuffer + bplength - 16, sizeof(uint64_t));
	memcpy(&offset_table_index, bpbuffer + bplength - 8, sizeof(uint64_t));
	byte_convert((char *) &num_objects, sizeof(uint64_t));
	byte_convert((char *) &root_object, sizeof(uint64_t));
	byte_convert((char *) &offset_table_index, sizeof(uint64_t));

	log_debug_msg("Offset size: %i\nGiven: %i\n", offset_size, bpbuffer[bplength - 26]);
	log_debug_msg("Ref size: %i\nGiven: %i\n", dict_param_size, bpbuffer[bplength - 25]);
	log_debug_msg("Number of objects: %lli\nGiven: %llu\n", num_objects, *(bpbuffer + bplength - 24));
	log_debug_msg("Root object index: %lli\nGiven: %llu\n", root_object, *(bpbuffer + bplength - 16));
	log_debug_msg("Offset table index: %lli\nGiven: %llu\n", offset_table_index, *(bpbuffer + bplength - 8));
	log_debug_msg("Size of uint64: %i\n", sizeof(uint64_t));

	int i = 0, j = 0, k = 0, str_i = 0, str_j = 0;
	uint32_t index1 = 0, index2 = 0;

	nodeslist = (plist_t *) malloc(sizeof(plist_t) * num_objects);
	if (!nodeslist)
		return NULL;

	for (i = 0; i < num_objects; i++) {
		memcpy(&current_offset, bpbuffer + (offset_table_index + (i * offset_size)), offset_size);
		byte_convert((char *) &current_offset,
					 (offset_size <= sizeof(current_offset)) ? offset_size : sizeof(current_offset));
		log_debug_msg("parse_nodes: current_offset = %x\n", current_offset);
		nodeslist[i] = parse_raw_node(bpbuffer, bplength, (uint32_t *) & current_offset, dict_param_size);
		log_debug_msg("parse_nodes: parse_raw_node done\n");
	}


	for (i = 0; i < num_objects; i++) {
		// set elements for dicts and arrays and leave the rest alone
		log_debug_msg("parse_nodes: on node %i\n", i);
		struct plist_data *data = (struct plist_data *) nodeslist[i]->data;

		switch (data->type) {
		case PLIST_DICT:
			log_debug_msg("parse_nodes: dictionary found\n");
			for (j = 0; j < (data->length / 2); j++) {
				str_i = j * data->ref_size;
				str_j = (j + (data->length / 2)) * data->ref_size;

				memcpy(&index1, data->buff + str_i, data->ref_size);
				memcpy(&index2, data->buff + str_j, data->ref_size);

				byte_convert((char *) &index1, (dict_param_size <= sizeof(index1)) ? dict_param_size : sizeof(index2));
				byte_convert((char *) &index2, (dict_param_size <= sizeof(index2)) ? dict_param_size : sizeof(index2));

				g_node_append(nodeslist[i], nodeslist[index1]);
				g_node_append(nodeslist[i], nodeslist[index2]);
			}

			data->length = data->length / 2;
			free(data->buff);
			k = 0;
			break;

		case PLIST_ARRAY:
			log_debug_msg("parse_nodes: array found\n");
			for (j = 0; j < data->length; j++) {
				log_debug_msg("parse_nodes: array index %i\n", j);
				str_j = j * data->ref_size;
				memcpy(&index1, data->buff + str_j, data->ref_size);
				log_debug_msg("parse_nodes: post-memcpy\n");
				byte_convert((char *) &index1, (dict_param_size <= sizeof(index1)) ? dict_param_size : sizeof(index1));
				log_debug_msg("parse_nodes: post-ntohl\nindex1 = %i\n", index1);
				g_node_append(nodeslist[i], nodeslist[index1]);
				log_debug_msg("parse_nodes: post-assignment\n");
			}
			free(data->buff);
			break;
		default:
			//printf("lol... type %x\n", nodeslist[i]->type);
			break;
		}						// those are the only two we need to correct for.
	}

	root_node = nodeslist[root_object];
	return root_node;
}

void plist_to_bin(plist_t plist, char **plist_bin, int *length)
{
}

void xml_to_plist(const char *plist_xml, plist_t * plist)
{
	xmlDocPtr plist_doc = xmlReadMemory(plist_xml, strlen(plist_xml), NULL, NULL, 0);
	xmlNodePtr root_node = xmlDocGetRootElement(plist_doc);

	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);
	*plist = g_node_new(data);
	data->type = PLIST_PLIST;
	xml_to_node(root_node, *plist);

}

void bin_to_plist(const char *plist_bin, int length, plist_t * plist)
{
	uint32_t pos = 0;
	*plist = parse_nodes(plist_bin, length, &pos);
}
