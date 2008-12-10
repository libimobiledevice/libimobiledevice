/*
 * main.c for plistutil
 * right now just prints debug shit
 */

#include "../src/plist.h"
#include "plutil.h"
#include <glib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


int main(int argc, char *argv[])
{
	struct stat *filestats = (struct stat *) malloc(sizeof(struct stat));
	uint32_t position = 0;
	Options *options = parse_arguments(argc, argv);
	int argh = 0;

	if (!options) {
		print_usage();
		return 0;
	}

	iphone_set_debug(options->debug);

	FILE *bplist = fopen(options->in_file, "r");

	stat(options->in_file, filestats);

	char *bplist_entire = (char *) malloc(sizeof(char) * (filestats->st_size + 1));
	argh = fread(bplist_entire, sizeof(char), filestats->st_size, bplist);
	fclose(bplist);
	// bplist_entire contains our stuff

	plist_t root_node = NULL;
	char *plist_out = NULL;
	int size = 0;

	if (memcmp(bplist_entire, "bplist00", 8) == 0) {
		bin_to_plist(bplist_entire, filestats->st_size, &root_node);
		plist_to_xml(root_node, &plist_out, &size);
	} else {
		xml_to_plist(bplist_entire, filestats->st_size, &root_node);
		plist_to_bin(root_node, &plist_out, &size);
	}


	printf("%s\n", plist_out);
	return 0;
}

Options *parse_arguments(int argc, char *argv[])
{
	int i = 0;

	Options *options = (Options *) malloc(sizeof(Options));
	memset(options, 0, sizeof(Options));

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--infile") || !strcmp(argv[i], "-i")) {
			if ((i + 1) == argc) {
				free(options);
				return NULL;
			}
			options->in_file = argv[i + 1];
			i++;
			continue;
		}

		if (!strcmp(argv[i], "--outfile") || !strcmp(argv[i], "-o")) {
			if ((i + 1) == argc) {
				free(options);
				return NULL;
			}
			options->out_file = argv[i + 1];
			i++;
			continue;
		}

		if (!strcmp(argv[i], "--debug") || !strcmp(argv[i], "-d") || !strcmp(argv[i], "-v")) {
			options->debug = 1;
		}

		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			free(options);
			return NULL;
		}
	}

	if (!options->in_file /*|| !options->out_file */ ) {
		free(options);
		return NULL;
	}

	return options;
}

void print_usage()
{
	printf("Usage: plistutil -i|--infile in_file.plist -o|--outfile out_file.plist [--debug]\n");
	printf("\n");
	printf("\t-i or --infile: The file to read in.\n");
	printf("\t-o or --outfile: The file to convert to.\n");
	printf("\t-d, -v or --debug: Provide extended debug information.\n\n");
}
