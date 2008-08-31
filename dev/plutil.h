
/* 
 * main.h - header for plistutil
 * Written by FxChiP
 */

typedef struct _options {
	char *in_file, *out_file;
	uint8_t debug, in_fmt, out_fmt;
} Options;

Options *parse_arguments(int argc, char *argv[]);
void print_usage();
