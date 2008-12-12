/*
 * plist.c
 * Binary plist implementation
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


#include "plist.h"
#include <wchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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

#define get_needed_bytes(x) (x <= 1<<8 ? 1 : ( x <= 1<<16 ? 2 : ( x <= 1<<32 ? 4 : 8)))
#define get_real_bytes(x) (x >> 32 ? 4 : 8)

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

guint plist_data_hash(gconstpointer key)
{
	struct plist_data *data = (struct plist_data *) ((GNode *) key)->data;

	guint hash = data->type;
	guint i = 0;

	char *buff = NULL;
	guint size = 0;

	switch (data->type) {
	case PLIST_BOOLEAN:
	case PLIST_UINT:
	case PLIST_REAL:
		buff = (char *) &data->intval;
		size = 8;
		break;
	case PLIST_KEY:
	case PLIST_STRING:
		buff = data->strval;
		size = strlen(buff);
		break;
	case PLIST_UNICODE:
		buff = data->unicodeval;
		size = strlen(buff) * sizeof(wchar_t);
		break;
	case PLIST_DATA:
	case PLIST_ARRAY:
	case PLIST_DICT:
		//for these types only hash pointer
		buff = &key;
		size = sizeof(gconstpointer);
		break;
	case PLIST_DATE:
	default:
		break;
	}

	//now perform hash
	for (i = 0; i < size; buff++, i++)
		hash = hash << 7 ^ (*buff);

	return hash;
}

gboolean plist_data_compare(gconstpointer a, gconstpointer b)
{
	if (!a || !b)
		return FALSE;

	if (!((GNode *) a)->data || !((GNode *) b)->data)
		return FALSE;

	struct plist_data *val_a = (struct plist_data *) ((GNode *) a)->data;
	struct plist_data *val_b = (struct plist_data *) ((GNode *) b)->data;

	if (val_a->type != val_b->type)
		return FALSE;

	switch (val_a->type) {
	case PLIST_BOOLEAN:
	case PLIST_UINT:
	case PLIST_REAL:
		if (val_a->intval == val_b->intval)	//it is an union so this is sufficient
			return TRUE;
		else
			return FALSE;

	case PLIST_KEY:
	case PLIST_STRING:
		if (!strcmp(val_a->strval, val_b->strval))
			return TRUE;
		else
			return FALSE;
	case PLIST_UNICODE:
		if (!strcmp(val_a->unicodeval, val_b->unicodeval))
			return TRUE;
		else
			return FALSE;

	case PLIST_DATA:
	case PLIST_ARRAY:
	case PLIST_DICT:
		//compare pointer
		if (a == b)
			return TRUE;
		else
			return FALSE;
		break;
	case PLIST_DATE:
	default:
		break;
	}
	return FALSE;
}

struct serialize_s {
	GPtrArray *objects;
	GHashTable *ref_table;
};

void serialize_plist(GNode * node, gpointer data)
{
	struct serialize_s *ser = (struct serialize_s *) data;
	uint64_t current_index = ser->objects->len;

	//first check that node is not yet in objects
	gpointer val = g_hash_table_lookup(ser->ref_table, node);
	if (val) {
		//data is already in table
		return;
	}
	//insert new ref
	g_hash_table_insert(ser->ref_table, node, GUINT_TO_POINTER(current_index));

	//now append current node to object array
	g_ptr_array_add(ser->objects, node);

	//now recurse on children
	g_node_children_foreach(node, G_TRAVERSE_ALL, serialize_plist, data);
	return;
}

#define Log2(x) (x == 8 ? 3 : (x == 4 ? 2 : (x == 2 ? 1 : 0)))

void write_int(GByteArray * bplist, uint64_t val)
{
	uint64_t size = get_needed_bytes(val);
	uint8_t *buff = (uint8_t *) malloc(sizeof(uint8_t) + size);
	buff[0] = BPLIST_UINT | Log2(size);
	memcpy(buff + 1, &val, size);
	byte_convert(buff + 1, size);
	g_byte_array_append(bplist, buff, sizeof(uint8_t) + size);
	free(buff);
}

void write_real(GByteArray * bplist, double val)
{
	uint64_t size = get_real_bytes(*((uint64_t *) & val));	//cheat to know used space
	uint8_t *buff = (uint8_t *) malloc(sizeof(uint8_t) + size);
	buff[0] = BPLIST_REAL | Log2(size);
	memcpy(buff + 1, &val, size);
	byte_convert(buff + 1, size);
	g_byte_array_append(bplist, buff, sizeof(uint8_t) + size);
	free(buff);
}

void write_raw_data(GByteArray * bplist, uint8_t mark, uint8_t * val, uint64_t size)
{
	uint8_t marker = mark | (size < 15 ? size : 0xf);
	g_byte_array_append(bplist, &marker, sizeof(uint8_t));
	if (size >= 15) {
		GByteArray *int_buff = g_byte_array_new();
		write_int(int_buff, size);
		g_byte_array_append(bplist, int_buff->data, int_buff->len);
		g_byte_array_free(int_buff, TRUE);
	}
	uint8_t *buff = (uint8_t *) malloc(size);
	memcpy(buff, val, size);
	g_byte_array_append(bplist, buff, size);
	free(buff);
}

void write_data(GByteArray * bplist, uint8_t * val, uint64_t size)
{
	write_raw_data(bplist, BPLIST_DATA, val, size);
}

void write_string(GByteArray * bplist, char *val)
{
	uint64_t size = strlen(val);
	write_raw_data(bplist, BPLIST_STRING, val, size);
}

void write_array(GByteArray * bplist, GNode * node, GHashTable * ref_table, uint8_t dict_param_size)
{
	uint64_t size = g_node_n_children(node);
	uint8_t marker = BPLIST_ARRAY | (size < 15 ? size : 0xf);
	g_byte_array_append(bplist, &marker, sizeof(uint8_t));
	if (size >= 15) {
		GByteArray *int_buff = g_byte_array_new();
		write_int(int_buff, size);
		g_byte_array_append(bplist, int_buff->data, int_buff->len);
		g_byte_array_free(int_buff, TRUE);
	}

	uint64_t idx = 0;
	uint8_t *buff = (uint8_t *) malloc(size * dict_param_size);

	GNode *cur = NULL;
	int i = 0;
	for (i = 0, cur = node->children; cur && i < size; cur = cur->next, i++) {
		idx = GPOINTER_TO_UINT(g_hash_table_lookup(ref_table, cur));
		memcpy(buff + i * dict_param_size, &idx, dict_param_size);
		byte_convert(buff + i * dict_param_size, dict_param_size);
	}

	//now append to bplist
	g_byte_array_append(bplist, buff, size * dict_param_size);
	free(buff);

}

void write_dict(GByteArray * bplist, GNode * node, GHashTable * ref_table, uint8_t dict_param_size)
{
	uint64_t size = g_node_n_children(node) / 2;
	uint8_t marker = BPLIST_DICT | (size < 15 ? size : 0xf);
	g_byte_array_append(bplist, &marker, sizeof(uint8_t));
	if (size >= 15) {
		GByteArray *int_buff = g_byte_array_new();
		write_int(int_buff, size);
		g_byte_array_append(bplist, int_buff->data, int_buff->len);
		g_byte_array_free(int_buff, TRUE);
	}

	uint64_t idx1 = 0;
	uint64_t idx2 = 0;
	uint8_t *buff = (uint8_t *) malloc(size * 2 * dict_param_size);

	GNode *cur = NULL;
	int i = 0;
	for (i = 0, cur = node->children; cur && i < size; cur = cur->next->next, i++) {
		idx1 = GPOINTER_TO_UINT(g_hash_table_lookup(ref_table, cur));
		memcpy(buff + i * dict_param_size, &idx1, dict_param_size);
		byte_convert(buff + i * dict_param_size, dict_param_size);

		idx2 = GPOINTER_TO_UINT(g_hash_table_lookup(ref_table, cur->next));
		memcpy(buff + (i + size) * dict_param_size, &idx2, dict_param_size);
		byte_convert(buff + (i + size) * dict_param_size, dict_param_size);
	}

	//now append to bplist
	g_byte_array_append(bplist, buff, size * 2 * dict_param_size);
	free(buff);

}

void plist_to_bin(plist_t plist, char **plist_bin, uint32_t * length)
{
	//check for valid input
	if (!plist || !plist_bin || *plist_bin || !length)
		return;

	//list of objects
	GPtrArray *objects = g_ptr_array_new();
	//hashtable to write only once same nodes
	GHashTable *ref_table = g_hash_table_new(plist_data_hash, plist_data_compare);

	//serialize plist
	struct serialize_s ser_s = { objects, ref_table };
	serialize_plist(plist, &ser_s);

	//now stream to output buffer
	uint8_t offset_size = 0;	//unknown yet
	uint8_t dict_param_size = get_needed_bytes(objects->len);
	uint64_t num_objects = objects->len;
	uint64_t root_object = 0;	//root is first in list
	uint64_t offset_table_index = 0;	//unknown yet

	//setup a dynamic bytes array to store bplist in
	GByteArray *bplist_buff = g_byte_array_new();

	//set magic number and version
	g_byte_array_append(bplist_buff, BPLIST_MAGIC, BPLIST_MAGIC_SIZE);
	g_byte_array_append(bplist_buff, BPLIST_VERSION, BPLIST_VERSION_SIZE);

	//write objects and table
	int i = 0;
	uint8_t *buff = NULL;
	uint8_t size = 0;
	uint64_t offsets[num_objects];
	for (i = 0; i < num_objects; i++) {

		offsets[i] = bplist_buff->len;
		struct plist_data *data = (struct plist_data *) ((GNode *) g_ptr_array_index(objects, i))->data;

		switch (data->type) {
		case PLIST_BOOLEAN:
			buff = (uint8_t *) malloc(sizeof(uint8_t));
			buff[0] = data->boolval ? BPLIST_TRUE : BPLIST_FALSE;
			g_byte_array_append(bplist_buff, buff, sizeof(uint8_t));
			free(buff);
			break;

		case PLIST_UINT:
			write_int(bplist_buff, data->intval);
			break;

		case PLIST_REAL:
			write_real(bplist_buff, data->realval);
			break;

		case PLIST_KEY:
		case PLIST_STRING:
			write_string(bplist_buff, data->strval);
			break;
		case PLIST_UNICODE:
			//TODO
			break;
		case PLIST_DATA:
			write_data(bplist_buff, data->strval, data->length);
		case PLIST_ARRAY:
			write_array(bplist_buff, g_ptr_array_index(objects, i), ref_table, dict_param_size);
			break;
		case PLIST_DICT:
			write_dict(bplist_buff, g_ptr_array_index(objects, i), ref_table, dict_param_size);
			break;
		case PLIST_DATE:
			//TODO
			break;
		default:
			break;
		}
	}

	//write offsets
	offset_size = get_needed_bytes(bplist_buff->len);
	offset_table_index = bplist_buff->len;
	for (i = 0; i <= num_objects; i++) {
		uint8_t *buff = (uint8_t *) malloc(offset_size);
		memcpy(buff, offsets + i, offset_size);
		byte_convert(buff, offset_size);
		g_byte_array_append(bplist_buff, buff, offset_size);
		free(buff);
	}

	//setup trailer
	num_objects = bswap_64(num_objects);
	root_object = bswap_64(root_object);
	offset_table_index = bswap_64(offset_table_index);

	char trailer[BPLIST_TRL_SIZE];
	memcpy(trailer + BPLIST_TRL_OFFSIZE_IDX, &offset_size, sizeof(uint8_t));
	memcpy(trailer + BPLIST_TRL_PARMSIZE_IDX, &dict_param_size, sizeof(uint8_t));
	memcpy(trailer + BPLIST_TRL_NUMOBJ_IDX, &num_objects, sizeof(uint64_t));
	memcpy(trailer + BPLIST_TRL_ROOTOBJ_IDX, &root_object, sizeof(uint64_t));
	memcpy(trailer + BPLIST_TRL_OFFTAB_IDX, &offset_table_index, sizeof(uint64_t));

	g_byte_array_append(bplist_buff, trailer, BPLIST_TRL_SIZE);

	//duplicate buffer
	*plist_bin = (char *) malloc(bplist_buff->len);
	memcpy(*plist_bin, bplist_buff->data, bplist_buff->len);
	*length = bplist_buff->len;

	g_byte_array_free(bplist_buff, TRUE);
}
