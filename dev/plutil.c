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

	printf("plistutil version 0.2 written by FxChiP\n");

	if (!options) {
		print_usage();
		return 0;
	}

	iphone_set_debug(options->debug);

	FILE *bplist = fopen(options->in_file, "r");

	stat(options->in_file, filestats);

	printf("here?\n");
	char *bplist_entire = (char *) malloc(sizeof(char) * (filestats->st_size + 1));
	//argh = fgets(bplist_entire, filestats->st_size, bplist);
	argh = fread(bplist_entire, sizeof(char), filestats->st_size, bplist);
	printf("read %i bytes\n", argh);
	fclose(bplist);
	printf("or here?\n");
	// bplist_entire contains our stuff
	plist_t root_node = NULL;
	bin_to_plist(bplist_entire, filestats->st_size, &root_node);
	printf("plutil debug mode\n\n");
	printf("file size %i\n\n", (int) filestats->st_size);
	if (!root_node) {
		printf("Invalid binary plist (or some other error occurred.)\n");
		return 0;
	}
	char *plist_xml = NULL;
	int size = 0;
	plist_to_xml(root_node, &plist_xml, &size);
	printf("%s\n", plist_xml);
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
