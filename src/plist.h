/*
 * plist.h
 * contains structures and the like for plists
 *
 * Copyright (c) 2008 Zack C. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>. 
 */

#ifndef PLIST_H
#define PLIST_H

#include <libxml/parser.h>
#include <libxml/tree.h>

xmlNode *add_key_str_dict_element(xmlDocPtr plist, xmlNode *dict, const char *key, const char *value, int depth);
xmlNode *add_child_to_plist(xmlDocPtr plist, const char *name, const char *content, xmlNode *to_node, int depth);
void free_plist(xmlDocPtr plist);
xmlDocPtr new_plist();
void free_dictionary(char **dictionary);
#endif
