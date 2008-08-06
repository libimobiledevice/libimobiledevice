/*
 * plist.h
 * contains structures and the like for plists
 *
 * Copyright (c) 2008 Zack C. All Rights Reserved.
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

xmlNode *add_key_dict_node(xmlDocPtr plist, xmlNode *dict, const char *key, const char *value, int depth);
xmlNode *add_key_str_dict_element(xmlDocPtr plist, xmlNode *dict, const char *key, const char *value, int depth);
xmlNode *add_key_data_dict_element(xmlDocPtr plist, xmlNode *dict, const char *key, const char *value, int depth);
xmlNode *add_child_to_plist(xmlDocPtr plist, const char *name, const char *content, xmlNode *to_node, int depth);
void free_plist(xmlDocPtr plist);
xmlDocPtr new_plist();
char **read_dict_element_strings(xmlNode *dict);
void free_dictionary(char **dictionary);
char **read_dict_element_strings(xmlNode *dict);
#endif
