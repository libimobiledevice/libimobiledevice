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

bplist_node *parse_raw_node(const char *bpbuffer, uint32_t bplength, uint32_t * position, uint8_t ref_size)
{
	if (!position || !bpbuffer || !bplength)
		return NULL;

	uint8_t modifier = 0;
	bplist_node *new_node = (bplist_node *) malloc(sizeof(bplist_node));
	bplist_node *length_stupidity = NULL;
	memset(new_node, 0, sizeof(bplist_node));	// initialize the new struct

	int myPos = *position;
	if (myPos == bplength || (myPos + 1) == bplength) {
		free(new_node);
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
		new_node->type = BPLIST_DATE;
		new_node->length = 8;	// always 8 for "date" (Apple intended it, not me)
		myPos++;
		memcpy(&new_node->realval, bpbuffer + myPos, sizeof(new_node->realval));
		byte_convert((char *) &new_node->realval, sizeof(new_node->realval));
		myPos += new_node->length;
		*position = myPos;
		return new_node;
	}

	new_node->type = bpbuffer[myPos] & BPLIST_MASK;
	new_node->length = bpbuffer[myPos] & BPLIST_FILL;
	if (!new_node->type) {
		// what? check if it's a boolean.
		if (bpbuffer[myPos] == BPLIST_TRUE || bpbuffer[myPos] == BPLIST_FALSE) {
			// okay, so it is. Carry on.
			new_node->type = bpbuffer[myPos];
			new_node->length = 0;
		} else {
			// er, what? we have a bad type here. Return NULL.
			free(new_node);
			//printf("parse_raw_node: lol type: type given %x\n", bpbuffer[myPos]);
			return NULL;
		}
	}

	myPos++;					// puts us in the data.
	if (new_node->length == BPLIST_FILL) {	// Data happens to contain length...
		// what? you're going to make me parse an int for the length. You suck.
		*position = myPos;
		length_stupidity = parse_raw_node(bpbuffer, bplength, &myPos, ref_size);
		switch (length_stupidity->length) {
		case sizeof(uint8_t):
			new_node->length = length_stupidity->intval8;
			break;
		case sizeof(uint16_t):
			new_node->length = length_stupidity->intval16;
			break;
		case sizeof(uint32_t):
			new_node->length = length_stupidity->intval32;
			break;
		case sizeof(uint64_t):
			new_node->length = length_stupidity->intval64;
			break;
		default:
			free(new_node);
			free(length_stupidity);
			return NULL;
		}
		// There, we have our fucking length now.
		*position = myPos;
		free(length_stupidity);	// cleanup
	}
	// Now we're in the data. 
	// Error-checking sorta
	if ((myPos + new_node->length) >= bplength) {
		new_node->length = bplength - myPos;	// truncate the object
	}
	// And now for the greatest show on earth: the giant fucking switch statement.
	switch (new_node->type) {
	case BPLIST_INT:
		new_node->length = uipow(2, new_node->length);	// make length less misleading
		switch (new_node->length) {
		case sizeof(uint8_t):
			new_node->intval8 = bpbuffer[myPos];
			break;
		case sizeof(uint16_t):
			memcpy(&new_node->intval16, bpbuffer + myPos, sizeof(uint16_t));
			new_node->intval16 = ntohs(new_node->intval16);
			break;
		case sizeof(uint32_t):
			memcpy(&new_node->intval32, bpbuffer + myPos, sizeof(uint32_t));
			new_node->intval32 = ntohl(new_node->intval32);
			break;
		case sizeof(uint64_t):
			memcpy(&new_node->intval64, bpbuffer + myPos, sizeof(uint64_t));
			byte_convert((char *) &new_node->intval64, sizeof(uint64_t));
			break;
		default:
			free(new_node);
			printf("parse_raw_node: lol: invalid int: size given %lu\n", (long unsigned int) new_node->length);
			printf("parse_raw_node: lol: by the way sizeof(uint64) = %i\n", sizeof(uint64_t));
			return NULL;
		}
		break;

	case BPLIST_REAL:
		new_node->length = uipow(2, new_node->length);
		memcpy(&new_node->realval, bpbuffer + myPos, new_node->length);	// XXX: probable buffer overflow here
		//new_node->realval = bpbuffer[myPos]; // why not
		byte_convert((char *) &new_node->realval, sizeof(double));
		break;

	case BPLIST_DICT:			/* returning a raw dict, it forward-references, so. */
		new_node->length = new_node->length * 2;	// dicts lie
	case BPLIST_ARRAY:			/* returning a raw array, it forward-references, so. */
		new_node->intval8 = ref_size;	// in arrays and dicts, the "ref size" alluded to in the trailer applies, and should be stored in intval8 so as to save space. 
	case BPLIST_STRING:
	case BPLIST_DATA:
	default:					/* made to hold raw data. */
		modifier = (new_node->intval8 > 0) ? new_node->intval8 : 1;
		new_node->strval = (char *) malloc(sizeof(char) * (new_node->length * modifier));
		memcpy(new_node->strval, bpbuffer + myPos, (new_node->length * modifier));
		break;

	case BPLIST_UNICODE:
		new_node->unicodeval = (wchar_t *) malloc(sizeof(wchar_t) * new_node->length);
		memcpy(new_node->unicodeval, bpbuffer + myPos, new_node->length);
		break;
	}

	myPos += new_node->length;
	*position = myPos;
	return new_node;
}

void print_bytes(char *val, size_t size)
{
	int i = 0;
	for (i = 0; i < size; i++) {
		printf("Byte %i: 0x%x\n", i, val[i]);
	}
}

bplist_node *parse_nodes(const char *bpbuffer, uint32_t bplength, uint32_t * position)
{
	bplist_node **nodeslist = NULL, **newaddr = NULL;
	bplist_node *new_node = NULL, *root_node = NULL;

	uint32_t nodeslength = 0;
	uint8_t offset_size = 0, dict_param_size = 0;
	offset_size = bpbuffer[bplength - 26];
	dict_param_size = bpbuffer[bplength - 25];
	uint64_t current_offset = 0;
	//uint64_t num_objects = *(bpbuffer+(bplength-24)), root_object = *(bpbuffer+(bplength-16)), offset_table_index = *(bpbuffer+(bplength-8));
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

	nodeslist = (bplist_node **) malloc(sizeof(bplist_node *) * num_objects);
	if (!nodeslist)
		return NULL;

	for (i = 0; i < num_objects; i++) {
		memcpy(&current_offset, bpbuffer + (offset_table_index + (i * offset_size)), offset_size);
		//current_offset = (offset_size == 2) ? ntohs(current_offset) : (offset_size == 4) ? ntohl(current_offset) : current_offset;
		//if (offset_size == 8) byte_convert(&current_offset, 8);
		byte_convert((char *) &current_offset,
					 (offset_size <= sizeof(current_offset)) ? offset_size : sizeof(current_offset));
		log_debug_msg("parse_nodes: current_offset = %x\n", current_offset);
		nodeslist[i] = parse_raw_node(bpbuffer, bplength, (uint32_t *) & current_offset, dict_param_size);
		log_debug_msg("parse_nodes: parse_raw_node done\n");
	}


	for (i = 0; i < num_objects; i++) {
		// set elements for dicts and arrays and leave the rest alone
		log_debug_msg("parse_nodes: on node %i\n", i);
		switch (nodeslist[i]->type) {
		case BPLIST_DICT:
			log_debug_msg("parse_nodes: dictionary found\n");
			nodeslist[i]->subnodes = (bplist_node **) malloc(sizeof(bplist_node) * nodeslist[i]->length);
			for (j = 0; j < (nodeslist[i]->length / 2); j++) {
				str_i = j * nodeslist[i]->intval8;
				str_j = (j + (nodeslist[i]->length / 2)) * nodeslist[i]->intval8;

				memcpy(&index1, nodeslist[i]->strval + str_i, nodeslist[i]->intval8);
				memcpy(&index2, nodeslist[i]->strval + str_j, nodeslist[i]->intval8);
				//index1 = (dict_param_size == 1) ? index1 : (dict_param_size == 2) ? ntohs(index1) : (dict_param_size == 4) ? ntohl(index1) : index1;
				//index2 = (dict_param_size == 1) ? index2 : (dict_param_size == 2) ? ntohs(index2) : (dict_param_size == 4) ? ntohl(index2) : index2;
				byte_convert((char *) &index1, (dict_param_size <= sizeof(index1)) ? dict_param_size : sizeof(index2));
				byte_convert((char *) &index2, (dict_param_size <= sizeof(index2)) ? dict_param_size : sizeof(index2));
				//printf("parse_nodes: key index %i value %i\n", index1, index2);
				//printf("parse_nodes: key type %x and length %i\n", nodeslist[index1]->type, nodeslist[index1]->length);
				//printf("parse_nodes: value type %x and length %i\n", nodeslist[index2]->type, nodeslist[index2]->length);
				nodeslist[i]->subnodes[k++] = nodeslist[index1];
				nodeslist[i]->subnodes[k++] = nodeslist[index2];
			}

			nodeslist[i]->length = nodeslist[i]->length / 2;
			free(nodeslist[i]->strval);
			k = 0;
			break;

		case BPLIST_ARRAY:
			log_debug_msg("parse_nodes: array found\n");
			nodeslist[i]->subnodes = (bplist_node **) malloc(sizeof(bplist_node) * nodeslist[i]->length);	// memory allocation helps a lot when storing data

			for (j = 0; j < nodeslist[i]->length; j++) {
				log_debug_msg("parse_nodes: array index %i\n", j);
				str_j = j * nodeslist[i]->intval8;
				//index1 = nodeslist[i]->strval[j];
				memcpy(&index1, nodeslist[i]->strval + str_j, nodeslist[i]->intval8);
				log_debug_msg("parse_nodes: post-memcpy\n");
				//index1 = (dict_param_size == 1) ? index1 : (dict_param_size == 2) ? ntohs(index1) : (dict_param_size == 4) ? ntohl(index1) : index1;
				byte_convert((char *) &index1, (dict_param_size <= sizeof(index1)) ? dict_param_size : sizeof(index1));
				log_debug_msg("parse_nodes: post-ntohl\nindex1 = %i\n", index1);
				nodeslist[i]->subnodes[j] = nodeslist[index1];
				log_debug_msg("parse_nodes: post-assignment\n");
			}
			free(nodeslist[i]->strval);
			break;
		default:
			//printf("lol... type %x\n", nodeslist[i]->type);
			break;
		}						// those are the only two we need to correct for.
	}

	root_node = nodeslist[root_object];
	return root_node;
}
