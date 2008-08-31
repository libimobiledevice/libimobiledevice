/*
 * main.c for plistutil
 * right now just prints debug shit
 */

#include "../src/plist.h"
#include "plutil.h"

int debug = 0;

void print_nodes(bplist_node *root_node) {
	// Yay, great. Let's print the list of nodes recursively...
	int i = 0;
	if (!root_node) return; // or not, because the programmer's stupid.
	
	switch (root_node->type) {
		case BPLIST_DICT:
			printf("Dictionary node.\nLength %i\n", root_node->length);
			for (i = 0; i < (root_node->length * 2); i+=2) {
				// HI!
				printf("Key: ");
				print_nodes(root_node->subnodes[i]);
				printf("Value: ");
				print_nodes(root_node->subnodes[i+1]);
			}
			printf("End dictionary node.\n\n");
			break;
		
		case BPLIST_ARRAY:
			printf("Array node.\n");
			for (i = 0; i < root_node->length; i++) {
				printf("\tElement %i: ", i);
				print_nodes(root_node->subnodes[i]);
			}
			break;
			
		case BPLIST_INT:
			if (root_node->length == sizeof(uint8_t)) {
				printf("Integer: %i\n", root_node->intval8);
			} else if (root_node->length == sizeof(uint16_t)) {
				printf("Integer: %i\n", root_node->intval16);
			} else if (root_node->length == sizeof(uint32_t)) {
				printf("Integer: %i\n", root_node->intval32);
			}
			break;
		
		case BPLIST_STRING:
			printf("String: ");
			fwrite(root_node->strval, sizeof(char), root_node->length, stdout);
			fflush(stdout);
			printf("\n");
			break;

		case BPLIST_DATA:
			printf("Data: ");
			char* data = g_base64_encode(root_node->strval,root_node->length);
			fwrite(format_string(data, 60, 0), sizeof(char), strlen(data), stdout);
			fflush(stdout);
			printf("\n");
			break;
		
		case BPLIST_UNICODE:
			printf("Unicode data, may appear crappy: ");
			fwrite(root_node->unicodeval, sizeof(wchar_t), root_node->length, stdout);
			fflush(stdout);
			printf("\n");
			break;
		
		case BPLIST_TRUE:
			printf("True.\n");
			break;
		
		case BPLIST_FALSE:
			printf("False.\n");
			break;
		
		case BPLIST_REAL:
		case BPLIST_DATE:
			printf("Real(?): %f\n", root_node->realval);
			break;
			
		default:
			printf("oops\nType set to %x and length is %i\n", root_node->type, root_node->length);
			break;
	}
}

int main(int argc, char *argv[]) {
	struct stat *filestats = (struct stat *)malloc(sizeof(struct stat));
	uint32_t position = 0;
	Options *options = parse_arguments(argc, argv);
	int argh = 0;
	
	printf("plistutil version 0.2 written by FxChiP\n");
	
	if (!options) {
		print_usage();
		return 0;
	}

	debug = options->debug;
	
	FILE *bplist = fopen(options->in_file, "r");
	
	stat(options->in_file, filestats);

	printf("here?\n");
	char *bplist_entire = (char*)malloc(sizeof(char) * (filestats->st_size + 1));
	//argh = fgets(bplist_entire, filestats->st_size, bplist);
	argh = fread(bplist_entire, sizeof(char), filestats->st_size, bplist);
	printf("read %i bytes\n", argh);
	fclose(bplist);
	printf("or here?\n");
	// bplist_entire contains our stuff
	 bplist_node *root_node;
	 root_node = parse_nodes(bplist_entire, filestats->st_size, &position);
	 printf("plutil debug mode\n\n");
	 printf("file size %i\n\n", filestats->st_size);
	 if (!root_node) {
	 	printf("Invalid binary plist (or some other error occurred.)\n");
	 	return 0;
	}
	 print_nodes(root_node);
	 return 0;
 }

Options *parse_arguments(int argc, char *argv[]) {
	int i = 0;
	
	Options *options = (Options*)malloc(sizeof(Options));
	memset(options, 0, sizeof(Options));
	
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--infile") || !strcmp(argv[i], "-i")) {
			if ((i+1) == argc) {
				free(options);
				return NULL;
			}
			options->in_file = argv[i+1];
			i++;
			continue;
		}
		
		if (!strcmp(argv[i], "--outfile") || !strcmp(argv[i], "-o")) {
			if ((i+1) == argc) {
				free(options);
				return NULL;
			}
			options->out_file = argv[i+1];
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
	
	if (!options->in_file /*|| !options->out_file*/) {
		free(options);
		return NULL;
	}
	
	return options;
}

void print_usage() {
	printf("Usage: plistutil -i|--infile in_file.plist -o|--outfile out_file.plist [--debug]\n");
	printf("\n");
	printf("\t-i or --infile: The file to read in.\n");
	printf("\t-o or --outfile: The file to convert to.\n");
	printf("\t-d, -v or --debug: Provide extended debug information.\n\n");
}
