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
#include <stdlib.h>
#include <stdio.h>


void plist_new_dict(plist_t * plist)
{
	if (*plist != NULL)
		return;
	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);
	data->type = PLIST_DICT;
	*plist = g_node_new(data);
}

void plist_new_array(plist_t * plist)
{
	if (*plist != NULL)
		return;
	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);
	data->type = PLIST_ARRAY;
	*plist = g_node_new(data);
}

void plist_new_dict_in_plist(plist_t plist, plist_t * dict)
{
	if (!plist || *dict)
		return;

	struct plist_data *data = (struct plist_data *) calloc(sizeof(struct plist_data), 1);
	data->type = PLIST_DICT;
	*dict = g_node_new(data);
	g_node_append(plist, *dict);
}


/** Adds a new key pair to a dict.
 *
 * @param dict The dict node in the plist.
 * @param key the key name of the key pair.
 * @param type The the type of the value in the key pair.
 * @param value a pointer to the actual buffer containing the value. WARNING : the buffer is supposed to match the type of the value
 *
 */
void plist_add_dict_element(plist_t dict, char *key, plist_type type, void *value)
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

plist_t find_query_node(plist_t plist, char *key, char *request)
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
		if (data->type == PLIST_DICT || data->type == PLIST_ARRAY) {
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
	default:
		break;
	}
	return res;
}

plist_t find_node(plist_t plist, plist_type type, void *value)
{
	if (!plist)
		return NULL;

	GNode *current = NULL;
	for (current = plist->children; current; current = current->next) {

		struct plist_data *data = (struct plist_data *) current->data;

		if (data->type == type && compare_node_value(type, data, value)) {
			return current;
		}
		if (data->type == PLIST_DICT || data->type == PLIST_ARRAY) {
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
	default:
		break;
	}
}

plist_type plist_get_node_type(plist_t node)
{
	if (node && node->data)
		return ((struct plist_data *) node->data)->type;
	else
		return PLIST_NONE;
}

uint64_t plist_get_node_uint_val(plist_t node)
{
	if (PLIST_UINT == plist_get_node_type(node))
		return ((struct plist_data *) node->data)->intval;
	else
		return 0;
}
