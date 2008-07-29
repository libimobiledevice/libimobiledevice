/* plist.h
 * contains structures and the like for plists
 * written by fxchip
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
