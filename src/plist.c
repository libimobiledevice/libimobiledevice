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


#include <string.h>
#include <assert.h>
#include "utils.h"
#include "plist.h"
#include <wchar.h>

/**********************************************
*                                             *
*           Abstract Plist stuff              *
*                                             *
**********************************************/







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
		uint64_t intval;
		double realval;
		char *strval;
		wchar_t *unicodeval;
		char *buff;
	};
	uint64_t length;
	plist_type type;
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

/** Adds a new key pair to a dict.
 *
 * @param dict The dict node in the plist.
 * @param key the key name of the key pair.
 * @param type The the type of the value in the key pair.
 * @param value a pointer to the actual buffer containing the value. WARNING : the buffer is supposed to match the type of the value
 *
 */
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
	case PLIST_UINT:
		val->intval = *((uint64_t *) value);
		break;
	case PLIST_REAL:
		val->realval = *((double *) value);
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

/**********************************************
*                                             *
*              Xml Plist stuff                *
*                                             *
**********************************************/

#include <libxml/parser.h>
#include <libxml/tree.h>


const char *plist_base = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
</plist>\0";

struct xml_node {
	xmlNodePtr xml;
	uint32_t depth;
};

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

void node_to_xml(GNode * node, gpointer xml_struct)
{
	if (!node)
		return;

	struct xml_node *xstruct = (struct xml_node *) xml_struct;
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

	case PLIST_UINT:
		tag = "integer";
		val = g_strdup_printf("%lu", (long unsigned int) node_data->intval);
		break;

	case PLIST_REAL:
		tag = "real";
		val = g_strdup_printf("%Lf", (long double) node_data->realval);
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
		val = format_string(node_data->buff, 60, xstruct->depth);
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

	int i = 0;
	for (i = 0; i < xstruct->depth; i++) {
		xmlNodeAddContent(xstruct->xml, "\t");
	}
	child_node = xmlNewChild(xstruct->xml, NULL, tag, val);
	xmlNodeAddContent(xstruct->xml, "\n");
	g_free(val);

	//add return for structured types
	if (node_data->type == PLIST_ARRAY ||
		node_data->type == PLIST_DICT || node_data->type == PLIST_DATA || node_data->type == PLIST_PLIST)
		xmlNodeAddContent(child_node, "\n");

	if (isStruct) {
		struct xml_node child = { child_node, xstruct->depth + 1 };
		g_node_children_foreach(node, G_TRAVERSE_ALL, node_to_xml, &child);
	}
	//fix indent for structured types
	if (node_data->type == PLIST_ARRAY ||
		node_data->type == PLIST_DICT || node_data->type == PLIST_DATA || node_data->type == PLIST_PLIST) {

		for (i = 0; i < xstruct->depth; i++) {
			xmlNodeAddContent(child_node, "\t");
		}
	}

	return;
}

void xml_to_node(xmlNodePtr xml_node, GNode * plist_node)
{
	xmlNodePtr node = NULL;

	for (node = xml_node->children; node; node = node->next) {

		while (node && !xmlStrcmp(node->name, "text"))
			node = node->next;
		if (!node)
			break;

		struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);
		GNode *subnode = g_node_new(data);
		g_node_append(plist_node, subnode);

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
			data->intval = atoi(strval);
			data->type = PLIST_UINT;
			continue;
		}

		if (!xmlStrcmp(node->name, "real")) {
			char *strval = xmlNodeGetContent(node);
			data->realval = atof(strval);
			data->type = PLIST_REAL;
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

void plist_to_xml(plist_t plist, char **plist_xml, uint32_t * length)
{
	if (!plist || !plist_xml || *plist_xml)
		return;
	xmlDocPtr plist_doc = new_plist();
	xmlNodePtr root_node = xmlDocGetRootElement(plist_doc);
	struct xml_node root = { root_node, 0 };
	g_node_children_foreach(plist, G_TRAVERSE_ALL, node_to_xml, &root);
	xmlDocDumpMemory(plist_doc, (xmlChar **) plist_xml, length);
}

void xml_to_plist(const char *plist_xml, uint32_t length, plist_t * plist)
{
	xmlDocPtr plist_doc = xmlReadMemory(plist_xml, length, NULL, NULL, 0);
	xmlNodePtr root_node = xmlDocGetRootElement(plist_doc);

	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);
	*plist = g_node_new(data);
	data->type = PLIST_PLIST;
	xml_to_node(root_node, *plist);
}



/**********************************************
*                                             *
*            Binary Plist stuff               *
*                                             *
**********************************************/

/* Magic marker and size. */
#define BPLIST_MAGIC		"bplist"
#define BPLIST_MAGIC_SIZE	6

#define BPLIST_VERSION		"00"
#define BPLIST_VERSION_SIZE	2


#define BPLIST_TRL_SIZE 	26
#define BPLIST_TRL_OFFSIZE_IDX 	0
#define BPLIST_TRL_PARMSIZE_IDX 1
#define BPLIST_TRL_NUMOBJ_IDX 	2
#define BPLIST_TRL_ROOTOBJ_IDX 	10
#define BPLIST_TRL_OFFTAB_IDX 	18

enum {
	BPLIST_NULL = 0x00,
	BPLIST_TRUE = 0x08,
	BPLIST_FALSE = 0x09,
	BPLIST_FILL = 0x0F,			/* will be used for length grabbing */
	BPLIST_UINT = 0x10,
	BPLIST_REAL = 0x20,
	BPLIST_DATE = 0x30,
	BPLIST_DATA = 0x40,
	BPLIST_STRING = 0x50,
	BPLIST_UNICODE = 0x60,
	BPLIST_UID = 0x70,
	BPLIST_ARRAY = 0xA0,
	BPLIST_SET = 0xC0,
	BPLIST_DICT = 0xD0,
	BPLIST_MASK = 0xF0
};

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

#include <byteswap.h>
#define swap_n_bytes(x, n) \
		n == 8 ? bswap_64(*(uint64_t *)(x)) : \
		(n == 4 ? bswap_32(*(uint32_t *)(x)) : \
		(n == 2 ? bswap_16(*(uint16_t *)(x)) : *(x) ))

#define be64dec(x) bswap_64( *(uint64_t*)(x) )

GNode *parse_uint_node(char *bnode, uint8_t size, char **next_object)
{
	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);

	size = 1 << size;			// make length less misleading
	switch (size) {
	case sizeof(uint8_t):
		data->intval = bnode[0];
		break;
	case sizeof(uint16_t):
		memcpy(&data->intval, bnode, size);
		data->intval = ntohs(data->intval);
		break;
	case sizeof(uint32_t):
		memcpy(&data->intval, bnode, size);
		data->intval = ntohl(data->intval);
		break;
	case sizeof(uint64_t):
		memcpy(&data->intval, bnode, size);
		byte_convert((char *) &data->intval, size);
		break;
	default:
		free(data);
		return NULL;
	};

	*next_object = bnode + size;
	data->type = PLIST_UINT;
	return g_node_new(data);
}

GNode *parse_real_node(char *bnode, uint8_t size)
{
	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);

	size = 1 << size;			// make length less misleading
	switch (size) {
	case sizeof(float):
		memcpy(&data->realval, bnode, size);
		byte_convert((char *) &data->realval, size);
		break;
	case sizeof(double):
		memcpy(&data->realval, bnode, size);
		byte_convert((char *) &data->realval, size);
		break;
	default:
		free(data);
		return NULL;
	}
	data->type = PLIST_REAL;
	return g_node_new(data);
}

GNode *parse_string_node(char *bnode, uint8_t size)
{
	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);

	data->type = PLIST_STRING;
	data->strval = (char *) malloc(sizeof(char) * (size + 1));
	memcpy(data->strval, bnode, size);
	data->strval[size] = '\0';

	return g_node_new(data);
}

GNode *parse_unicode_node(char *bnode, uint8_t size)
{
	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);

	data->type = PLIST_UNICODE;
	data->unicodeval = (wchar_t *) malloc(sizeof(wchar_t) * (size + 1));
	memcpy(data->unicodeval, bnode, size);
	data->unicodeval[size] = '\0';

	return g_node_new(data);
}

GNode *parse_data_node(char *bnode, uint64_t size, uint32_t ref_size)
{
	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);

	data->type = PLIST_DATA;
	data->length = size;
	data->buff = (char *) malloc(sizeof(char) * size);
	memcpy(data->buff, bnode, sizeof(char) * size);

	return g_node_new(data);
}

GNode *parse_dict_node(char *bnode, uint64_t size, uint32_t ref_size)
{
	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);

	data->type = PLIST_DICT;
	data->length = size;
	data->buff = (char *) malloc(sizeof(char) * size * ref_size * 2);
	memcpy(data->buff, bnode, sizeof(char) * size * ref_size * 2);

	return g_node_new(data);
}

GNode *parse_array_node(char *bnode, uint64_t size, uint32_t ref_size)
{
	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);

	data->type = PLIST_ARRAY;
	data->length = size;
	data->buff = (char *) malloc(sizeof(char) * size * ref_size);
	memcpy(data->buff, bnode, sizeof(char) * size * ref_size);

	return g_node_new(data);
}

plist_type plist_get_node_type(plist_t node)
{
	return ((struct plist_data *) node->data)->type;
}

uint64_t plist_get_node_uint_val(plist_t node)
{
	if (PLIST_UINT == plist_get_node_type(node))
		return ((struct plist_data *) node->data)->intval;
	else
		return 0;
}


GNode *parse_bin_node(char *object, uint8_t dict_size, char **next_object)
{
	if (!object)
		return NULL;

	uint16_t type = *object & 0xF0;
	uint64_t size = *object & 0x0F;
	object++;

	switch (type) {

	case BPLIST_NULL:
		switch (size) {

		case BPLIST_TRUE:
			{
				struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);
				data->type = PLIST_BOOLEAN;
				data->boolval = TRUE;
				return g_node_new(data);
			}

		case BPLIST_FALSE:
			{
				struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);
				data->type = PLIST_BOOLEAN;
				data->boolval = FALSE;
				return g_node_new(data);
			}

		case BPLIST_NULL:
		default:
			return NULL;
		}

	case BPLIST_UINT:
		return parse_uint_node(object, size, next_object);

	case BPLIST_REAL:
		return parse_real_node(object, size);

	case BPLIST_DATE:
		if (3 != size)
			return NULL;
		else
			return parse_real_node(object, size);

	case BPLIST_DATA:
		if (0x0F == size) {
			plist_t size_node = parse_bin_node(object, dict_size, &object);
			if (plist_get_node_type(size_node) != PLIST_UINT)
				return NULL;
			size = plist_get_node_uint_val(size_node);
		}
		return parse_data_node(object, size, dict_size);

	case BPLIST_STRING:
		if (0x0F == size) {
			plist_t size_node = parse_bin_node(object, dict_size, &object);
			if (plist_get_node_type(size_node) != PLIST_UINT)
				return NULL;
			size = plist_get_node_uint_val(size_node);
		}
		return parse_string_node(object, size);

	case BPLIST_UNICODE:
		if (0x0F == size) {
			plist_t size_node = parse_bin_node(object, dict_size, &object);
			if (plist_get_node_type(size_node) != PLIST_UINT)
				return NULL;
			size = plist_get_node_uint_val(size_node);
		}
		return parse_unicode_node(object, size);

	case BPLIST_UID:
	case BPLIST_ARRAY:
		if (0x0F == size) {
			plist_t size_node = parse_bin_node(object, dict_size, &object);
			if (plist_get_node_type(size_node) != PLIST_UINT)
				return NULL;
			size = plist_get_node_uint_val(size_node);
		}
		return parse_array_node(object, size, dict_size);

	case BPLIST_SET:
	case BPLIST_DICT:
		if (0x0F == size) {
			plist_t size_node = parse_bin_node(object, dict_size, &object);
			if (plist_get_node_type(size_node) != PLIST_UINT)
				return NULL;
			object++;
			size = plist_get_node_uint_val(size_node);
		}
		return parse_dict_node(object, size, dict_size);

	}
	return NULL;
}

void plist_to_bin(plist_t plist, char **plist_bin, uint32_t * length)
{
	uint64_t num_objects = g_node_n_nodes(plist, G_TRAVERSE_ALL);
}



gpointer copy_plist_data(gconstpointer src, gpointer data)
{
	struct plist_data *srcdata = (struct plist_data *) src;
	struct plist_data *dstdata = (struct plist_data *) calloc(sizeof(struct plist_data), 1);

	dstdata->type = srcdata->type;
	dstdata->length = srcdata->length;
	switch (dstdata->type) {
	case PLIST_BOOLEAN:
		dstdata->boolval = srcdata->boolval;
		break;
	case PLIST_UINT:
		dstdata->intval = srcdata->intval;
		break;
	case PLIST_DATE:
	case PLIST_REAL:
		dstdata->realval = srcdata->realval;
		break;
	case PLIST_KEY:
	case PLIST_STRING:
		dstdata->strval = strdup(srcdata->strval);
		break;
	case PLIST_UNICODE:
		dstdata->unicodeval = wcsdup(srcdata->unicodeval);
		break;
	case PLIST_PLIST:
	case PLIST_DATA:
	case PLIST_ARRAY:
	case PLIST_DICT:
		dstdata->buff = (char *) malloc(sizeof(char *) * srcdata->length);
		memcpy(dstdata->buff, srcdata->buff, sizeof(char *) * srcdata->length);
		break;

	default:
		break;
	}

	return dstdata;
}

void bin_to_plist(const char *plist_bin, uint32_t length, plist_t * plist)
{
	//first check we have enough data
	if (!(length >= BPLIST_MAGIC_SIZE + BPLIST_VERSION_SIZE + BPLIST_TRL_SIZE))
		return;
	//check that plist_bin in actually a plist
	if (memcmp(plist_bin, BPLIST_MAGIC, BPLIST_MAGIC_SIZE) != 0)
		return;
	//check for known version
	if (memcmp(plist_bin + BPLIST_MAGIC_SIZE, BPLIST_VERSION, BPLIST_VERSION_SIZE) != 0)
		return;

	//now parse trailer
	const char *trailer = plist_bin + (length - BPLIST_TRL_SIZE);

	uint8_t offset_size = trailer[BPLIST_TRL_OFFSIZE_IDX];
	uint8_t dict_param_size = trailer[BPLIST_TRL_PARMSIZE_IDX];
	uint64_t num_objects = be64dec(trailer + BPLIST_TRL_NUMOBJ_IDX);
	uint64_t root_object = be64dec(trailer + BPLIST_TRL_ROOTOBJ_IDX);
	uint64_t offset_table_index = be64dec(trailer + BPLIST_TRL_OFFTAB_IDX);

	log_debug_msg("Offset size: %i\n", offset_size);
	log_debug_msg("Ref size: %i\n", dict_param_size);
	log_debug_msg("Number of objects: %lli\n", num_objects);
	log_debug_msg("Root object index: %lli\n", root_object);
	log_debug_msg("Offset table index: %lli\n", offset_table_index);

	if (num_objects == 0)
		return;

	//allocate serialized array of nodes
	plist_t *nodeslist = NULL;
	nodeslist = (plist_t *) malloc(sizeof(plist_t) * num_objects);

	if (!nodeslist)
		return;

	//parse serialized nodes
	uint64_t i = 0;
	uint64_t current_offset = 0;
	const char *offset_table = plist_bin + offset_table_index;
	for (i = 0; i < num_objects; i++) {
		current_offset = swap_n_bytes(offset_table + i * offset_size, offset_size);

		log_debug_msg("parse_nodes: current_offset = %i\n", current_offset);
		char *obj = plist_bin + current_offset;
		nodeslist[i] = parse_bin_node(obj, dict_param_size, &obj);
		log_debug_msg("parse_nodes: parse_raw_node done\n");
	}

	//setup children for structured types
	int j = 0, str_i = 0, str_j = 0;
	uint32_t index1 = 0, index2 = 0;

	for (i = 0; i < num_objects; i++) {

		log_debug_msg("parse_nodes: on node %i\n", i);
		struct plist_data *data = (struct plist_data *) nodeslist[i]->data;

		switch (data->type) {
		case PLIST_DICT:
			log_debug_msg("parse_nodes: dictionary found\n");
			for (j = 0; j < data->length; j++) {
				str_i = j * dict_param_size;
				str_j = (j + data->length) * dict_param_size;

				index1 = swap_n_bytes(data->buff + str_i, dict_param_size);
				index2 = swap_n_bytes(data->buff + str_j, dict_param_size);

				//first one is actually a key
				((struct plist_data *) nodeslist[index1]->data)->type = PLIST_KEY;
				//g_node_append(nodeslist[i], nodeslist[index1]);
				//g_node_append(nodeslist[i], nodeslist[index2]);

				if (G_NODE_IS_ROOT(nodeslist[index1]))
					g_node_append(nodeslist[i], nodeslist[index1]);
				else
					g_node_append(nodeslist[i], g_node_copy_deep(nodeslist[index1], copy_plist_data, NULL));

				if (G_NODE_IS_ROOT(nodeslist[index2]))
					g_node_append(nodeslist[i], nodeslist[index2]);
				else
					g_node_append(nodeslist[i], g_node_copy_deep(nodeslist[index2], copy_plist_data, NULL));
			}

			free(data->buff);
			break;

		case PLIST_ARRAY:
			log_debug_msg("parse_nodes: array found\n");
			for (j = 0; j < data->length; j++) {
				str_j = j * dict_param_size;
				index1 = swap_n_bytes(data->buff + str_j, dict_param_size);

				//g_node_append(nodeslist[i], nodeslist[index1]);
				if (G_NODE_IS_ROOT(nodeslist[index1]))
					g_node_append(nodeslist[i], nodeslist[index1]);
				else
					g_node_append(nodeslist[i], g_node_copy_deep(nodeslist[index1], copy_plist_data, NULL));
			}
			free(data->buff);
			break;
		default:
			break;
		}
	}

	*plist = nodeslist[root_object];
}


GNode *find_query_node(plist_t plist, char *key, char *request)
{
	if (!plist)
		return NULL;

	GNode *current = NULL;
	for (current = plist->children; current; current = current->next) {

		struct plist_data *data = (struct plist_data *) current->data;

		if (data->type == PLIST_KEY && !strcmp(data->strval, key) && current->next) {

			data = (struct plist_data *) current->next->data;
			if (data->type == PLIST_STRING && !strcmp(data->strval, request))
				return current->next;
		}
		if (data->type == PLIST_DICT || data->type == PLIST_ARRAY || data->type == PLIST_PLIST) {
			GNode *sub = find_query_node(current, key, request);
			if (sub)
				return sub;
		}
	}
	return NULL;
}

char compare_node_value(plist_type type, struct plist_data *data, void *value)
{
	char res = FALSE;
	switch (type) {
	case PLIST_BOOLEAN:
		res = data->boolval == *((char *) value) ? TRUE : FALSE;
		break;
	case PLIST_UINT:
		res = data->intval == *((uint64_t *) value) ? TRUE : FALSE;
		break;
	case PLIST_REAL:
		res = data->realval == *((double *) value) ? TRUE : FALSE;
		break;
	case PLIST_KEY:
	case PLIST_STRING:
		res = !strcmp(data->strval, ((char *) value));
		break;
	case PLIST_UNICODE:
		res = !wcscmp(data->unicodeval, ((wchar_t *) value));
		break;
	case PLIST_DATA:
		res = !strcmp(data->buff, ((char *) value));
		break;
	case PLIST_ARRAY:
	case PLIST_DICT:
	case PLIST_DATE:
	case PLIST_PLIST:
	default:
		break;
	}
	return res;
}

GNode *find_node(plist_t plist, plist_type type, void *value)
{
	if (!plist)
		return NULL;

	GNode *current = NULL;
	for (current = plist->children; current; current = current->next) {

		struct plist_data *data = (struct plist_data *) current->data;

		if (data->type == type && compare_node_value(type, data, value)) {
			return current;
		}
		if (data->type == PLIST_DICT || data->type == PLIST_ARRAY || data->type == PLIST_PLIST) {
			GNode *sub = find_node(current, type, value);
			if (sub)
				return sub;
		}
	}
	return NULL;
}

void get_type_and_value(GNode * node, plist_type * type, void *value)
{
	if (!node)
		return;

	struct plist_data *data = (struct plist_data *) node->data;

	*type = data->type;

	switch (*type) {
	case PLIST_BOOLEAN:
		*((char *) value) = data->boolval;
		break;
	case PLIST_UINT:
		*((uint64_t *) value) = data->intval;
		break;
	case PLIST_REAL:
		*((double *) value) = data->realval;
		break;
	case PLIST_STRING:
		*((char **) value) = strdup(data->strval);
		break;
	case PLIST_UNICODE:
		*((wchar_t **) value) = wcsdup(data->unicodeval);
		break;
	case PLIST_KEY:
		*((char **) value) = strdup(data->strval);
		break;
	case PLIST_DATA:
	case PLIST_ARRAY:
	case PLIST_DICT:
	case PLIST_DATE:
	case PLIST_PLIST:
	default:
		break;
	}
}
