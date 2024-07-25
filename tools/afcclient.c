/*
 * afcclient.c
 * Utility to interact with AFC/HoustArrest service on the device
 *
 * Inspired by https://github.com/emonti/afcclient
 * But entirely rewritten from scratch.
 *
 * Copyright (c) 2023 Nikias Bassen, All Rights Reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define TOOL_NAME "afcclient"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <sys/time.h>
#include <conio.h>
#define sleep(x) Sleep(x*1000)
#define S_IFMT          0170000         /* [XSI] type of file mask */
#define S_IFIFO         0010000         /* [XSI] named pipe (fifo) */
#define S_IFCHR         0020000         /* [XSI] character special */
#define S_IFBLK         0060000         /* [XSI] block special */
#define S_IFLNK         0120000         /* [XSI] symbolic link */
#define S_IFSOCK        0140000         /* [XSI] socket */
#define S_ISBLK(m)      (((m) & S_IFMT) == S_IFBLK)     /* block special */
#define S_ISCHR(m)      (((m) & S_IFMT) == S_IFCHR)     /* char special */
#define S_ISFIFO(m)     (((m) & S_IFMT) == S_IFIFO)     /* fifo or socket */
#define S_ISLNK(m)      (((m) & S_IFMT) == S_IFLNK)     /* symbolic link */
#define S_ISSOCK(m)     (((m) & S_IFMT) == S_IFSOCK)    /* socket */
#else
#include <sys/time.h>
#include <termios.h>
#endif

#ifdef HAVE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/house_arrest.h>
#include <libimobiledevice/afc.h>
#include <plist/plist.h>

#include <libimobiledevice-glue/termcolors.h>
#include <libimobiledevice-glue/utils.h>

#undef st_mtime
#undef st_birthtime
struct afc_file_stat {
	uint16_t st_mode;
	uint16_t st_nlink;
	uint64_t st_size;
	uint64_t st_mtime;
	uint64_t st_birthtime;
	uint32_t st_blocks;
};

static char* udid = NULL;
static int connected = 0;
static int use_network = 0;
static idevice_subscription_context_t context = NULL;
static char* curdir = NULL;
static size_t curdir_len = 0;

static int file_exists(const char* path)
{
	struct stat tst;
#ifdef _WIN32
	return (stat(path, &tst) == 0);
#else
	return (lstat(path, &tst) == 0);
#endif
}

static int is_directory(const char* path)
{
	struct stat tst;
#ifdef _WIN32
	return (stat(path, &tst) == 0) && S_ISDIR(tst.st_mode);
#else
	return (lstat(path, &tst) == 0) && S_ISDIR(tst.st_mode);
#endif
}

static void print_usage(int argc, char **argv, int is_error)
{
	char *name = strrchr(argv[0], '/');
	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS]\n", (name ? name + 1: argv[0]));
	fprintf(is_error ? stderr : stdout,
		"\n"
		"Interact with AFC/HouseArrest service on a connected device.\n"
		"\n"
		"OPTIONS:\n"
		"  -u, --udid UDID       target specific device by UDID\n"
		"  -n, --network         connect to network device (not recommended!)\n"
		"  --container <appid>   Access container of given app\n"
		"  --documents <appid>   Access Documents directory of given app\n"
		"  -h, --help            prints usage information\n" \
		"  -d, --debug           enable communication debugging\n" \
		"  -v, --version         prints version information\n" \
		"\n"
	);
	fprintf(is_error ? stderr : stdout,
		"\n" \
		"Homepage:    <" PACKAGE_URL ">\n"
		"Bug Reports: <" PACKAGE_BUGREPORT ">\n"
	);
}

#ifndef HAVE_READLINE
#ifdef _WIN32
#define BS_CC '\b'
#else
#define BS_CC 0x7f
#define getch getchar
#endif
static void get_input(char *buf, int maxlen)
{
	int len = 0;
	int c;

	while ((c = getch())) {
		if ((c == '\r') || (c == '\n')) {
			break;
		}
		if (isprint(c)) {
			if (len < maxlen-1)
				buf[len++] = c;
		} else if (c == BS_CC) {
			if (len > 0) {
				fputs("\b \b", stdout);
				len--;
			}
		}
	}
	buf[len] = 0;
}
#endif

#define OPT_DOCUMENTS 1
#define OPT_CONTAINER 2

int stop_requested = 0;

static void handle_signal(int sig)
{
	stop_requested++;
#ifdef _WIN32
	GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
#else
	kill(getpid(), SIGINT);
#endif
}

static void handle_help(afc_client_t afc, int argc, char** argv)
{
	printf("Available commands:\n");
	printf("help - print list of available commands\n");
	printf("devinfo - print device information\n");
	printf("info PATH - print file attributes of file at PATH\n");
	printf("ls [-l] PATH - print directory contents of PATH\n");
	printf("mv OLD NEW - rename file OLD to NEW\n");
	printf("mkdir PATH - create directory at PATH\n");
	printf("ln [-s] FILE [LINK] - create a (symbolic) link to file named LINKNAME\n");
	printf("        NOTE: This feature has been disabled in newer versions of iOS.\n");
	printf("rm PATH - remove item at PATH\n");
	printf("get [-rf] PATH [LOCALPATH] - transfer file at PATH from device to LOCALPATH\n");
	printf("put [-rf] LOCALPATH [PATH] - transfer local file at LOCALPATH to device at PATH\n");
	printf("\n");
}

static const char* path_get_basename(const char* path)
{
	const char *p = strrchr(path, '/');
	return p ? p + 1 : path;
}

static int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}
	/* Compute the time remaining to wait.
	   tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;
	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}

struct str_item {
	size_t len;
	char* str;
};

static char* get_absolute_path(const char *path)
{
	if (*path == '/') {
		return strdup(path);
	} else {
		size_t len = curdir_len + 1 + strlen(path) + 1;
		char* result = (char*)malloc(len);
		if (!strcmp(curdir, "/")) {
			snprintf(result, len, "/%s", path);
		} else {
			snprintf(result, len, "%s/%s", curdir, path);
		}
		return result;
	}
}

static char* get_realpath(const char* path)
{
	if (!path) return NULL;

	int is_absolute = 0;
	if (*path == '/') {
		is_absolute = 1;
	}

	const char* p = path;
	if (is_absolute) {
		while (*p == '/') p++;
	}
	if (*p == '\0') {
		return strdup("/");
	}

	int c_count = 1;
	const char* start = p;
	const char* end = p;
	struct str_item* comps = NULL;

	while (*p) {
		if (*p == '/') {
			p++;
			end = p-1;
			while (*p == '/') p++;
			if (*p == '\0') break;
			struct str_item* newcomps = (struct str_item*)realloc(comps, sizeof(struct str_item)*c_count);
			if (!newcomps) {
				free(comps);
				printf("%s: out of memory?!\n", __func__);
				return NULL;
			}
			comps = newcomps;
			char *comp = (char*)malloc(end-start+1);
			strncpy(comp, start, end-start);
			comp[end-start] = '\0';
			comps[c_count-1].len = end-start;
			comps[c_count-1].str = comp;
			c_count++;
			start = p;
			end = p;
		}
		p++;
	}
	if (p > start) {
		if (start == end) {
			end = p;
		}
		struct str_item* newcomps = (struct str_item*)realloc(comps, sizeof(struct str_item)*c_count);
		if (!newcomps) {
			free(comps);
			printf("%s: out of memory?!\n", __func__);
			return NULL;
		}
		comps = newcomps;
		char *comp = (char*)malloc(end-start+1);
		strncpy(comp, start, end-start);
		comp[end-start] = '\0';
		comps[c_count-1].len = end-start;
		comps[c_count-1].str = comp;
	}

	struct str_item* comps_final = (struct str_item*)malloc(sizeof(struct str_item)*(c_count+1));
	int o = 1;
	if (is_absolute) {
		comps_final[0].len = 1;
		comps_final[0].str = (char*)"/";
	} else {
		comps_final[0].len = curdir_len;
		comps_final[0].str = curdir;
	}
	size_t o_len = comps_final[0].len;

	for (int i = 0; i < c_count; i++) {
		if (!strcmp(comps[i].str, "..")) {
			o--;
			continue;
		} else if (!strcmp(comps[i].str, ".")) {
			continue;
		}
		o_len += comps[i].len;
		comps_final[o].str = comps[i].str;
		comps_final[o].len = comps[i].len;
		o++;
	}

	o_len += o;
	char* result = (char*)malloc(o_len);
	char* presult = result;
	for (int i = 0; i < o; i++) {
		if (i > 0 && strcmp(comps_final[i-1].str, "/") != 0) {
			*presult = '/';
			presult++;
		}
		strncpy(presult, comps_final[i].str, comps_final[i].len);
		presult+=comps_final[i].len;
		*presult = '\0';
	}
	if (presult == result) {
		*presult = '/';
		presult++;
		*presult = 0;
	}

	for (int i = 0; i < c_count; i++) {
		free(comps[i].str);
	}
	free(comps);
	free(comps_final);

	return result;
}

static void handle_devinfo(afc_client_t afc, int argc, char** argv)
{
	char **info = NULL;
	afc_error_t err = afc_get_device_info(afc, &info);
	if (err == AFC_E_SUCCESS && info) {
		int i;
		for (i = 0; info[i]; i += 2) {
			printf("%s: %s\n", info[i], info[i+1]);
		}
	} else {
		printf("Error: Failed to get device info: %s (%d)\n", afc_strerror(err), err);
	}
	afc_dictionary_free(info);
}

static int get_file_info_stat(afc_client_t afc, const char* path, struct afc_file_stat *stbuf)
{
	char **info = NULL;
	afc_error_t ret = afc_get_file_info(afc, path, &info);
	memset(stbuf, 0, sizeof(struct afc_file_stat));
	if (ret != AFC_E_SUCCESS) {
		return -1;
	} else if (!info) {
		return -1;
	} else {
		// get file attributes from info list
		int i;
		for (i = 0; info[i]; i += 2) {
			if (!strcmp(info[i], "st_size")) {
				stbuf->st_size = atoll(info[i+1]);
			} else if (!strcmp(info[i], "st_blocks")) {
				stbuf->st_blocks = atoi(info[i+1]);
			} else if (!strcmp(info[i], "st_ifmt")) {
				if (!strcmp(info[i+1], "S_IFREG")) {
					stbuf->st_mode = S_IFREG;
				} else if (!strcmp(info[i+1], "S_IFDIR")) {
					stbuf->st_mode = S_IFDIR;
				} else if (!strcmp(info[i+1], "S_IFLNK")) {
					stbuf->st_mode = S_IFLNK;
				} else if (!strcmp(info[i+1], "S_IFBLK")) {
					stbuf->st_mode = S_IFBLK;
				} else if (!strcmp(info[i+1], "S_IFCHR")) {
					stbuf->st_mode = S_IFCHR;
				} else if (!strcmp(info[i+1], "S_IFIFO")) {
					stbuf->st_mode = S_IFIFO;
				} else if (!strcmp(info[i+1], "S_IFSOCK")) {
					stbuf->st_mode = S_IFSOCK;
				}
			} else if (!strcmp(info[i], "st_nlink")) {
				stbuf->st_nlink = atoi(info[i+1]);
			} else if (!strcmp(info[i], "st_mtime")) {
				stbuf->st_mtime = (time_t)(atoll(info[i+1]) / 1000000000);
			} else if (!strcmp(info[i], "st_birthtime")) { /* available on iOS 7+ */
				stbuf->st_birthtime = (time_t)(atoll(info[i+1]) / 1000000000);
			}
		}
		afc_dictionary_free(info);
	}
	return 0;
}

static void handle_file_info(afc_client_t afc, int argc, char** argv)
{
	if (argc < 1) {
		printf("Error: Missing PATH.\n");
		return;
	}

	char **info = NULL;
	char* abspath = get_absolute_path(argv[0]);
	if (!abspath) {
		printf("Error: Invalid argument\n");
		return;
	}
	afc_error_t err = afc_get_file_info(afc, abspath, &info);
	if (err == AFC_E_SUCCESS && info) {
		int i;
		for (i = 0; info[i]; i += 2) {
			printf("%s: %s\n", info[i], info[i+1]);
		}
	} else {
		printf("Error: Failed to get file info for %s: %s (%d)\n", argv[0], afc_strerror(err), err);
	}
	afc_dictionary_free(info);
	free(abspath);
}

static void print_file_info(afc_client_t afc, const char* path, int list_verbose)
{
	struct afc_file_stat st;
	get_file_info_stat(afc, path, &st);
	if (list_verbose) {
		char timebuf[64];
		time_t t = st.st_mtime;
		if (S_ISDIR(st.st_mode)) {
			printf("drwxr-xr-x");
		} else if (S_ISLNK(st.st_mode)) {
			printf("lrwxrwxrwx");
		} else {
			if (S_ISFIFO(st.st_mode)) {
				printf("f");
			} else if (S_ISBLK(st.st_mode)) {
				printf("b");
			} else if (S_ISCHR(st.st_mode)) {
				printf("c");
			} else if (S_ISSOCK(st.st_mode)) {
				printf("s");
			} else {
				printf("-");
			}
			printf("rw-r--r--");
		}
		printf(" ");
		printf("%4d", st.st_nlink);
		printf(" ");
		printf("mobile");
		printf(" ");
		printf("mobile");
		printf(" ");
		printf("%10lld", (long long)st.st_size);
		printf(" ");
#ifdef _WIN32
		strftime(timebuf, 64, "%d %b %Y %H:%M:%S", localtime(&t));
#else
		strftime(timebuf, 64, "%d %h %Y %H:%M:%S", localtime(&t));
#endif
		printf("%s", timebuf);
		printf(" ");
	}
	if (S_ISDIR(st.st_mode)) {
		cprintf(FG_CYAN);
	} else if (S_ISLNK(st.st_mode)) {
		cprintf(FG_MAGENTA);
	} else if (S_ISREG(st.st_mode)) {
		cprintf(FG_DEFAULT);
	} else {
		cprintf(FG_YELLOW);
	}
	cprintf("%s" COLOR_RESET "\n", path_get_basename(path));
}

static void handle_list(afc_client_t afc, int argc, char** argv)
{
	const char* path = NULL;
	int list_verbose = 0;
	if (argc < 1) {
		path = curdir;
	} else {
		if (!strcmp(argv[0], "-l")) {
			list_verbose = 1;
			if (argc == 2) {
				path = argv[1];
			} else {
				path = curdir;
			}
		} else {
			path = argv[0];
		}
	}
	char* abspath = get_absolute_path(path);
	if (!abspath) {
		printf("Error: Invalid argument\n");
		return;
	}
	int abspath_is_root = strcmp(abspath, "/") == 0;
	size_t abspath_len = (abspath_is_root) ? 0 : strlen(abspath);
	char** entries = NULL;
	afc_error_t err = afc_read_directory(afc, abspath, &entries);
	if (err == AFC_E_READ_ERROR) {
		print_file_info(afc, abspath, list_verbose);
		return;
	} else if (err != AFC_E_SUCCESS) {
		printf("Error: Failed to list '%s': %s (%d)\n", path, afc_strerror(err), err);
		free(abspath);
		return;
	}

	char** p = entries;
	while (p && *p) {
		if (strcmp(".", *p) == 0 || strcmp("..", *p) == 0) {
			p++;
			continue;
		}
		size_t len = abspath_len + 1 + strlen(*p) + 1;
		char* testpath = (char*)malloc(len);
		if (abspath_is_root) {
			snprintf(testpath, len, "/%s", *p);
		} else {
			snprintf(testpath, len, "%s/%s", abspath, *p);
		}
		print_file_info(afc, testpath, list_verbose);
		free(testpath);
		p++;
	}
	afc_dictionary_free(entries);
	free(abspath);
}

static void handle_rename(afc_client_t afc, int argc, char** argv)
{
	if (argc != 2) {
		printf("Error: Invalid number of arguments\n");
		return;
	}
	char* srcpath = get_absolute_path(argv[0]);
	if (!srcpath) {
		printf("Error: Invalid argument\n");
		return;
	}
	char* dstpath = get_absolute_path(argv[1]);
	if (!dstpath) {
		free(srcpath);
		printf("Error: Invalid argument\n");
		return;
	}
	afc_error_t err = afc_rename_path(afc, srcpath, dstpath);
	if (err != AFC_E_SUCCESS) {
		printf("Error: Failed to rename '%s' -> '%s': %s (%d)\n", argv[0], argv[1], afc_strerror(err), err);
	}
	free(srcpath);
	free(dstpath);
}

static void handle_mkdir(afc_client_t afc, int argc, char** argv)
{
	for (int i = 0; i < argc; i++) {
		char* abspath = get_absolute_path(argv[i]);
		if (!abspath) {
			printf("Error: Invalid argument '%s'\n", argv[i]);
			continue;
		}
		afc_error_t err = afc_make_directory(afc, abspath);
		if (err != AFC_E_SUCCESS) {
			printf("Error: Failed to create directory '%s': %s (%d)\n", argv[i], afc_strerror(err), err);
		}
		free(abspath);
	}
}

static void handle_link(afc_client_t afc, int argc, char** argv)
{
	if (argc < 2) {
		printf("Error: Invalid number of arguments\n");
		return;
	}
	afc_link_type_t link_type = AFC_HARDLINK;
	if (!strcmp(argv[0], "-s")) {
		argc--;
		argv++;
		link_type = AFC_SYMLINK;
	}
	if (argc < 1 || argc > 2) {
		printf("Error: Invalid number of arguments\n");
		return;
	}
	const char *link_name = (argc == 1) ? path_get_basename(argv[0]) : argv[1];
	char* abs_link_name = get_absolute_path(link_name);
	if (!abs_link_name) {
		printf("Error: Invalid argument\n");
		return;
	}
	afc_error_t err = afc_make_link(afc, link_type, argv[0], link_name);
	if (err != AFC_E_SUCCESS) {
		printf("Error: Failed to create %s link for '%s' at '%s': %s (%d)\n", (link_type == AFC_HARDLINK) ? "hard" : "symbolic", argv[0], link_name, afc_strerror(err), err);
	}
}

static int ask_yesno(const char* prompt)
{
	int ret = 0;
#ifdef HAVE_READLINE
	char* result = readline(prompt);
	if (result && result[0] == 'y') {
		ret = 1;
	}
#else
	char cmdbuf[2] = {0, };
	printf("%s", prompt);
	fflush(stdout);
	get_input(cmdbuf, sizeof(cmdbuf));
	if (cmdbuf[0] == 'y') {
		ret = 1;
	}
#endif
#ifdef HAVE_READLINE
	free(result);
#endif
	return ret;
}

static void handle_remove(afc_client_t afc, int argc, char** argv)
{
	int recursive = 0;
	int force = 0;
	int i = 0;
	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--")) {
			i++;
			break;
		} else if (!strcmp(argv[i], "-r")) {
			recursive = 1;
		} else if (!strcmp(argv[i], "-f")) {
			force = 1;
		} else if (!strcmp(argv[i], "-rf") || !strcmp(argv[i], "-fr")) {
			recursive = 1;
			force = 1;
		} else {
			break;
		}
	}
	if (recursive && !force) {
		if (!ask_yesno("WARNING: This operation will remove all contents of the given path(s). Continue? [y/N] ")) {
			printf("Aborted.\n");
			return;
		}
	}
	for ( ; i < argc; i++) {
		char* abspath = get_absolute_path(argv[i]);
		if (!abspath) {
			printf("Error: Invalid argument '%s'\n", argv[i]);
			continue;
		}
		afc_error_t err;
		if (recursive) {
			err = afc_remove_path_and_contents(afc, abspath);
		} else {
			err = afc_remove_path(afc, abspath);
		}
		if (err != AFC_E_SUCCESS) {
			printf("Error: Failed to remove '%s': %s (%d)\n", argv[i], afc_strerror(err), err);
		}
		free(abspath);
	}
}

static uint8_t get_single_file(afc_client_t afc, const char *srcpath, const char *dstpath, uint64_t file_size, uint8_t force_overwrite)
{
	uint64_t fh = 0;
	afc_error_t err = afc_file_open(afc, srcpath, AFC_FOPEN_RDONLY, &fh);
	if (err != AFC_E_SUCCESS) {
		printf("Error: Failed to open file '%s': %s (%d)\n", srcpath, afc_strerror(err), err);
		return 0;
	}
	if (file_exists(dstpath) && !force_overwrite) {
		printf("Error: Failed to overwrite existing file without '-f' option: %s\n", dstpath);
		return 0;
	}
	FILE *f = fopen(dstpath, "wb");
	if (!f) {
		printf("Error: Failed to open local file '%s': %s\n", dstpath, strerror(errno));
		return 0;
	}
	struct timeval t1;
	struct timeval t2;
	struct timeval tdiff;
	size_t bufsize = 0x100000;
	char *buf = malloc(bufsize);
	size_t total = 0;
	int progress = 0;
	int lastprog = 0;
	if (file_size > 0x400000) {
		progress = 1;
		gettimeofday(&t1, NULL);
	}
	uint8_t succeed = 1;
	while (err == AFC_E_SUCCESS) {
		uint32_t bytes_read = 0;
		size_t chunk = 0;
		err = afc_file_read(afc, fh, buf, bufsize, &bytes_read);
		if (bytes_read == 0) {
			break;
		}
		while (chunk < bytes_read) {
			size_t wr = fwrite(buf + chunk, 1, bytes_read - chunk, f);
			if (wr == 0) {
				if (progress) {
					printf("\n");
				}
				printf("Error: Failed to write to local file\n");
				succeed = 0;
				break;
			}
			chunk += wr;
		}
		total += chunk;
		if (progress) {
			int prog = (int) ((double) total / (double) file_size * 100.0f);
			if (prog > lastprog) {
				gettimeofday(&t2, NULL);
				timeval_subtract(&tdiff, &t2, &t1);
				double time_in_sec = (double) tdiff.tv_sec + (double) tdiff.tv_usec / 1000000;
				printf("\r%d%% (%0.1f MB/s)   ", prog, (double) total / 1048576.0f / time_in_sec);
				fflush(stdout);
				lastprog = prog;
			}
		}
	}
	if (progress) {
		printf("\n");
	}
	if (err != AFC_E_SUCCESS) {
		printf("Error: Failed to read from file '%s': %s (%d)\n", srcpath, afc_strerror(err), err);
		succeed = 0;
	}
	free(buf);
	fclose(f);
	afc_file_close(afc, fh);
	return succeed;
}

static int __mkdir(const char* path)
{
#ifdef _WIN32
	return mkdir(path);
#else
	return mkdir(path, 0755);
#endif
}

static uint8_t get_file(afc_client_t afc, const char *srcpath, const char *dstpath, uint8_t force_overwrite, uint8_t recursive_get)
{
	char **info = NULL;
	uint64_t file_size = 0;
	afc_error_t err = afc_get_file_info(afc, srcpath, &info);
	if (err == AFC_E_OBJECT_NOT_FOUND) {
		printf("Error: Failed to read from file '%s': %s (%d)\n", srcpath, afc_strerror(err), err);
		return 0;
	}
	uint8_t is_dir = 0;
	if (info) {
		char **p = info;
		while (p && *p) {
			if (!strcmp(*p, "st_size")) {
				p++;
				file_size = (uint64_t) strtoull(*p, NULL, 10);
			}
			if (!strcmp(*p, "st_ifmt")) {
				p++;
				is_dir = !strcmp(*p, "S_IFDIR");
			}
			p++;
		}
		afc_dictionary_free(info);
	}
	uint8_t succeed = 1;
	if (is_dir) {
		if (!recursive_get) {
			printf("Error: Failed to get a directory without '-r' option: %s\n", srcpath);
			return 0;
		}
		char **entries = NULL;
		err = afc_read_directory(afc, srcpath, &entries);
		if (err != AFC_E_SUCCESS) {
			printf("Error: Failed to list '%s': %s (%d)\n", srcpath, afc_strerror(err), err);
			return 0;
		}
		char **p = entries;
		size_t srcpath_len = strlen(srcpath);
		uint8_t srcpath_is_root = strcmp(srcpath, "/") == 0;
		// if directory exists, check force_overwrite flag
		if (is_directory(dstpath)) {
			if (!force_overwrite) {
				printf("Error: Failed to write into existing directory without '-f': %s\n", dstpath);
				return 0;
			}
		} else if (__mkdir(dstpath) != 0) {
			printf("Error: Failed to create directory '%s': %s\n", dstpath, strerror(errno));
			afc_dictionary_free(entries);
			return 0;
		}
		while (p && *p) {
			if (strcmp(".", *p) == 0 || strcmp("..", *p) == 0) {
				p++;
				continue;
			}
			size_t len = srcpath_is_root ? (strlen(*p) + 2) : (srcpath_len + 1 + strlen(*p) + 1);
			char *testpath = (char *) malloc(len);
			if (srcpath_is_root) {
				snprintf(testpath, len, "/%s", *p);
			} else {
				snprintf(testpath, len, "%s/%s", srcpath, *p);
			}
			uint8_t dst_is_root = strcmp(srcpath, "/") == 0;
			size_t dst_len = dst_is_root ? (strlen(*p) + 2) : (strlen(dstpath) + 1 + strlen(*p) + 1);
			char *newdst = (char *) malloc(dst_len);
			if (dst_is_root) {
				snprintf(newdst, dst_len, "/%s", *p);
			} else {
				snprintf(newdst, dst_len, "%s/%s", dstpath, *p);
			}
			if (!get_file(afc, testpath, newdst, force_overwrite, recursive_get)) {
				succeed = 0;
				break;
			}
			free(testpath);
			free(newdst);
			p++;
		}
		afc_dictionary_free(entries);
	} else {
		succeed = get_single_file(afc, srcpath, dstpath, file_size, force_overwrite);
	}
	return succeed;
}

static void handle_get(afc_client_t afc, int argc, char **argv)
{
	if (argc < 1) {
		printf("Error: Invalid number of arguments\n");
		return;
	}
	uint8_t force_overwrite = 0, recursive_get = 0;
	char *srcpath = NULL;
	char *dstpath = NULL;
	int i = 0;
	for ( ; i < argc; i++) {
		if (!strcmp(argv[i], "--")) {
			i++;
			break;
		} else if (!strcmp(argv[i], "-r")) {
			recursive_get = 1;
		} else if (!strcmp(argv[i], "-f")) {
			force_overwrite = 1;
		} else if (!strcmp(argv[i], "-rf") || !strcmp(argv[i], "-fr")) {
			recursive_get = 1;
			force_overwrite = 1;
		} else {
			break;
		}
	}
	if (argc - i == 1) {
		char *tmp = strdup(argv[i]);
		size_t src_len = strlen(tmp);
		if (src_len > 1 && tmp[src_len - 1] == '/') {
			tmp[src_len - 1] = '\0';
		}
		srcpath = get_absolute_path(tmp);
		dstpath = strdup(path_get_basename(tmp));
		free(tmp);
	} else if (argc - i == 2) {
		char *tmp = strdup(argv[i]);
		size_t src_len = strlen(tmp);
		if (src_len > 1 && tmp[src_len - 1] == '/') {
			tmp[src_len - 1] = '\0';
		}
		srcpath = get_absolute_path(tmp);
		dstpath = strdup(argv[i + 1]);
		size_t dst_len = strlen(dstpath);
		if (dst_len > 1 && dstpath[dst_len - 1] == '/') {
			dstpath[dst_len - 1] = '\0';
		}
		free(tmp);
	} else {
		printf("Error: Invalid number of arguments\n");
		return;
	}

	// target is a directory, put file under this target
	if (is_directory(dstpath)) {
		const char *basen = path_get_basename(srcpath);
		uint8_t dst_is_root = strcmp(dstpath, "/") == 0;
		size_t len = dst_is_root ? (strlen(basen) + 2) : (strlen(dstpath) + 1 + strlen(basen) + 1);
		char *newdst = (char *) malloc(len);
		if (dst_is_root) {
			snprintf(newdst, len, "/%s", basen);
		} else {
			snprintf(newdst, len, "%s/%s", dstpath, basen);
		}
		get_file(afc, srcpath, newdst, force_overwrite, recursive_get);
		free(srcpath);
		free(newdst);
		free(dstpath);
	} else {
		// target is not a dir or does not exist, just try to create or rewrite it
		get_file(afc, srcpath, dstpath, force_overwrite, recursive_get);
		free(srcpath);
		free(dstpath);
	}
}

static uint8_t put_single_file(afc_client_t afc, const char *srcpath, const char *dstpath, uint8_t force_overwrite)
{
	char **info = NULL;
	afc_error_t ret = afc_get_file_info(afc, dstpath, &info);
	// file exists, only overwrite with '-f' option was set
	if (ret == AFC_E_SUCCESS && info) {
		afc_dictionary_free(info);
		if (!force_overwrite) {
			printf("Error: Failed to write into existing file without '-f' option: %s\n", dstpath);
			return 0;
		}
	}
	FILE *f = fopen(srcpath, "rb");
	if (!f) {
		printf("Error: Failed to open local file '%s': %s\n", srcpath, strerror(errno));
		return 0;
	}
	struct timeval t1;
	struct timeval t2;
	struct timeval tdiff;
	struct stat fst;
	int progress = 0;
	size_t bufsize = 0x100000;
	char *buf = malloc(bufsize);

	fstat(fileno(f), &fst);
	if (fst.st_size >= 0x400000) {
		progress = 1;
		gettimeofday(&t1, NULL);
	}
	size_t total = 0;
	int lastprog = 0;
	uint64_t fh = 0;
	afc_error_t err = afc_file_open(afc, dstpath, AFC_FOPEN_RW, &fh);
	uint8_t succeed = 1;
	while (err == AFC_E_SUCCESS) {
		uint32_t bytes_read = fread(buf, 1, bufsize, f);
		if (bytes_read == 0) {
			if (!feof(f)) {
				if (progress) {
					printf("\n");
				}
				printf("Error: Failed to read from local file\n");
				succeed = 0;
			}
			break;
		}
		uint32_t chunk = 0;
		while (chunk < bytes_read) {
			uint32_t bytes_written = 0;
			err = afc_file_write(afc, fh, buf + chunk, bytes_read - chunk, &bytes_written);
			if (err != AFC_E_SUCCESS) {
				if (progress) {
					printf("\n");
				}
				printf("Error: Failed to write to device file\n");
				succeed = 0;
				break;
			}
			chunk += bytes_written;
		}
		total += chunk;
		if (progress) {
			int prog = (int) ((double) total / (double) fst.st_size * 100.0f);
			if (prog > lastprog) {
				gettimeofday(&t2, NULL);
				timeval_subtract(&tdiff, &t2, &t1);
				double time_in_sec = (double) tdiff.tv_sec + (double) tdiff.tv_usec / 1000000;
				printf("\r%d%% (%0.1f MB/s)   ", prog, (double) total / 1048576.0f / time_in_sec);
				fflush(stdout);
				lastprog = prog;
			}
		}
	}
	free(buf);
	afc_file_close(afc, fh);
	fclose(f);
	return succeed;
}

static uint8_t put_file(afc_client_t afc, const char *srcpath, const char *dstpath, uint8_t force_overwrite, uint8_t recursive_put)
{
	if (is_directory(srcpath)) {
		if (!recursive_put) {
			printf("Error: Failed to put directory without '-r' option: %s\n", srcpath);
			return 0;
		}
		char **info = NULL;
		afc_error_t err = afc_get_file_info(afc, dstpath, &info);
		//create if target directory does not exist
		afc_dictionary_free(info);
		if (err == AFC_E_OBJECT_NOT_FOUND) {
			err = afc_make_directory(afc, dstpath);
			if (err != AFC_E_SUCCESS) {
				printf("Error: Failed to create directory '%s': %s (%d)\n", dstpath, afc_strerror(err), err);
				return 0;
			}
		} else if (!force_overwrite) {
			printf("Error: Failed to put existing directory without '-f' option: %s\n", dstpath);
			return 0;
		}
		afc_get_file_info(afc, dstpath, &info);
		uint8_t is_dir = 0;
		if (info) {
			char **p = info;
			while (p && *p) {
				if (!strcmp(*p, "st_ifmt")) {
					p++;
					is_dir = !strcmp(*p, "S_IFDIR");
					break;
				}
				p++;
			}
			afc_dictionary_free(info);
		}
		if (!is_dir) {
			printf("Error: Failed to create or access directory: '%s'\n", dstpath);
			return 0;
		}

		// walk dir recursively to put files
		DIR *cur_dir = opendir(srcpath);
		if (cur_dir) {
			struct dirent *ep;
			while ((ep = readdir(cur_dir))) {
				if ((strcmp(ep->d_name, ".") == 0) || (strcmp(ep->d_name, "..") == 0)) {
					continue;
				}
				char *fpath = string_build_path(srcpath, ep->d_name, NULL);
				if (fpath) {
					uint8_t dst_is_root = strcmp(dstpath, "/") == 0;
					size_t len = dst_is_root ? (strlen(ep->d_name) + 2) : (strlen(dstpath) + 1 + strlen(ep->d_name) + 1);
					char *newdst = (char *) malloc(len);
					if (dst_is_root) {
						snprintf(newdst, len, "/%s", ep->d_name);
					} else {
						snprintf(newdst, len, "%s/%s", dstpath, ep->d_name);
					}
					if (!put_file(afc, fpath, newdst, force_overwrite, recursive_put)) {
						free(newdst);
						free(fpath);
						return 0;
					}
					free(newdst);
					free(fpath);
				}
			}
			closedir(cur_dir);
		} else {
			printf("Error: Failed to visit directory: '%s': %s\n", srcpath, strerror(errno));
			return 0;
		}
	} else {
		return put_single_file(afc, srcpath, dstpath, force_overwrite);
	}
	return 1;
}

static void handle_put(afc_client_t afc, int argc, char **argv)
{
	if (argc < 1) {
		printf("Error: Invalid number of arguments\n");
		return;
	}
	int i = 0;
	uint8_t force_overwrite = 0, recursive_put = 0;
	for ( ; i < argc; i++) {
		if (!strcmp(argv[i], "--")) {
			i++;
			break;
		} else if (!strcmp(argv[i], "-r")) {
			recursive_put = 1;
		} else if (!strcmp(argv[i], "-f")) {
			force_overwrite = 1;
		} else if (!strcmp(argv[i], "-rf") || !strcmp(argv[i], "-fr")) {
			recursive_put = 1;
			force_overwrite = 1;
		} else {
			break;
		}
	}
	if (i >= argc) {
		printf("Error: Invalid number of arguments\n");
		return;
	}
	char *srcpath = strdup(argv[i]);
	size_t src_len = strlen(srcpath);
	if (src_len > 1 && srcpath[src_len - 1] == '/') {
		srcpath[src_len - 1] = '\0';
	}
	char *dstpath = NULL;
	if (argc - i == 1) {
		dstpath = get_absolute_path(path_get_basename(srcpath));
	} else if (argc - i == 2) {
		char *tmp = strdup(argv[i + 1]);
		size_t dst_len = strlen(tmp);
		if (dst_len > 1 && tmp[dst_len - 1] == '/') {
			tmp[dst_len - 1] = '\0';
		}
		dstpath = get_absolute_path(tmp);
		free(tmp);
	} else {
		printf("Error: Invalid number of arguments\n");
		return;
	}
	char **info = NULL;
	afc_error_t err = afc_get_file_info(afc, dstpath, &info);
	// target does not exist, put directly
	if (err == AFC_E_OBJECT_NOT_FOUND) {
		put_file(afc, srcpath, dstpath, force_overwrite, recursive_put);
		free(srcpath);
		free(dstpath);
	} else {
		uint8_t is_dir = 0;
		if (info) {
			char **p = info;
			while (p && *p) {
				if (!strcmp(*p, "st_ifmt")) {
					p++;
					is_dir = !strcmp(*p, "S_IFDIR");
					break;
				}
				p++;
			}
			afc_dictionary_free(info);
		}
		// target is a directory, try to put under this directory
		if (is_dir) {
			const char *basen = path_get_basename(srcpath);
			uint8_t dst_is_root = strcmp(dstpath, "/") == 0;
			size_t len = dst_is_root ? (strlen(basen) + 2) : (strlen(dstpath) + 1 + strlen(basen) + 1);
			char *newdst = (char *) malloc(len);
			if (dst_is_root) {
				snprintf(newdst, len, "/%s", basen);
			} else {
				snprintf(newdst, len, "%s/%s", dstpath, basen);
			}
			free(dstpath);
			dstpath = get_absolute_path(newdst);
			free(newdst);
			put_file(afc, srcpath, dstpath, force_overwrite, recursive_put);
		} else {
			//target is common file, rewrite it
			put_file(afc, srcpath, dstpath, force_overwrite, recursive_put);
		}
		free(srcpath);
		free(dstpath);
	}
}

static void handle_pwd(afc_client_t afc, int argc, char** argv)
{
	printf("%s\n", curdir);
}

static void handle_cd(afc_client_t afc, int argc, char** argv)
{
	if (argc != 1) {
		printf("Error: Invalid number of arguments\n");
		return;
	}

	if (!strcmp(argv[0], ".")) {
		return;
	}

	if (!strcmp(argv[0], "..")) {
		if (!strcmp(curdir, "/")) {
			return;
		}
		char *p = strrchr(curdir, '/');
		if (!p) {
			strcpy(curdir, "/");
			return;
		}
		if (p == curdir) {
			*(p+1) = '\0';
		} else {
			*p = '\0';
		}
		return;
	}

	char* path = get_realpath(argv[0]);
	int is_dir = 0;
	char **info = NULL;
	afc_error_t err = afc_get_file_info(afc, path, &info);
	if (err == AFC_E_SUCCESS && info) {
		int i;
		for (i = 0; info[i]; i += 2) {
			if (!strcmp(info[i], "st_ifmt")) {
				if (!strcmp(info[i+1], "S_IFDIR")) {
					is_dir = 1;
				}
				break;
			}
		}
		afc_dictionary_free(info);
	} else {
		printf("Error: Failed to get file info for %s: %s (%d)\n", path, afc_strerror(err), err);
		free(path);
		return;
	}

	if (!is_dir) {
		printf("Error: '%s' is not a valid directory\n", path);
		free(path);
		return;
	}

	free(curdir);
	curdir = path;
	curdir_len = strlen(curdir);
}

static void parse_cmdline(int* p_argc, char*** p_argv, const char* cmdline)
{
	char **argv = NULL;
	int argc = 0;
	size_t maxlen = strlen(cmdline);
	const char* pos = cmdline;
	const char* qpos = NULL;
	char *tmpbuf = NULL;
	int tmplen = 0;
	int is_error = 0;

	/* skip initial whitespace */
	while (isspace(*pos)) pos++;
	maxlen -= (pos - cmdline);

	tmpbuf = (char*)malloc(maxlen+1);

	while (!is_error) {
		if (*pos == '\\') {
			pos++;
			switch (*pos) {
				case '"':
				case '\'':
				case '\\':
				case ' ':
					tmpbuf[tmplen++] = *pos;
					pos++;
					break;
				default:
					printf("Error: Invalid escape sequence\n");
					is_error++;
					break;
			}
		} else if (*pos == '"' || *pos == '\'') {
			if (!qpos) {
				qpos = pos;
			} else {
				qpos = NULL;
			}
			pos++;
		} else if (*pos == '\0' || (!qpos && isspace(*pos))) {
			tmpbuf[tmplen] = '\0';
			if (*pos == '\0' && qpos) {
				printf("Error: Unmatched `%c`\n", *qpos);
				is_error++;
				break;
			}
			char** new_argv = (char**)realloc(argv, (argc+1)*sizeof(char*));
			if (new_argv == NULL) {
				printf("Error: Out of memory?!\n");
				is_error++;
				break;
			}
			argv = new_argv;
			/* shrink buffer to actual argument size */
			argv[argc] = (char*)realloc(tmpbuf, tmplen+1);
			if (!argv[argc]) {
				printf("Error: Out of memory?!\n");
				is_error++;
				break;
			}
			argc++;
			tmpbuf = NULL;
			if (*pos == '\0') {
				break;
			}
			maxlen -= tmplen;
			tmpbuf = (char*)malloc(maxlen+1);
			tmplen = 0;
			while (isspace(*pos)) pos++;
		} else {
			tmpbuf[tmplen++] = *pos;
			pos++;
		}
	}
	if (tmpbuf) {
		free(tmpbuf);
	}
	if (is_error) {
		int i;
		for (i = 0; argv && i < argc; i++) free(argv[i]);
		free(argv);
		return;
	}

	*p_argv = argv;
	*p_argc = argc;
}

static int process_args(afc_client_t afc, int argc, char** argv)
{
	if (!strcmp(argv[0], "q") || !strcmp(argv[0], "quit") || !strcmp(argv[0], "exit")) {
		return -1;
	}
	else if (!strcmp(argv[0], "help")) {
		handle_help(afc, argc, argv);
	}
	else if (!strcmp(argv[0], "devinfo") || !strcmp(argv[0], "deviceinfo")) {
		handle_devinfo(afc, argc-1, argv+1);
	}
	else if (!strcmp(argv[0], "info")) {
		handle_file_info(afc, argc-1, argv+1);
	}
	else if (!strcmp(argv[0], "ls") || !strcmp(argv[0], "list")) {
		handle_list(afc, argc-1, argv+1);
	}
	else if (!strcmp(argv[0], "mv") || !strcmp(argv[0], "rename")) {
		handle_rename(afc, argc-1, argv+1);
	}
	else if (!strcmp(argv[0], "mkdir")) {
		handle_mkdir(afc, argc-1, argv+1);
	}
	else if (!strcmp(argv[0], "ln")) {
		handle_link(afc, argc-1, argv+1);
	}
	else if (!strcmp(argv[0], "rm") || !strcmp(argv[0], "remove")) {
		handle_remove(afc, argc-1, argv+1);
	}
	else if (!strcmp(argv[0], "get")) {
		handle_get(afc, argc-1, argv+1);
	}
	else if (!strcmp(argv[0], "put")) {
		handle_put(afc, argc-1, argv+1);
	}
	else if (!strcmp(argv[0], "pwd")) {
		handle_pwd(afc, argc-1, argv+1);
	}
	else if (!strcmp(argv[0], "cd")) {
		handle_cd(afc, argc-1, argv+1);
	}
	else {
		printf("Unknown command '%s'. Type 'help' to get a list of available commands.\n", argv[0]);
	}
	return 0;
}

static void start_cmdline(afc_client_t afc)
{
	while (!stop_requested) {
		int argc = 0;
		char **argv = NULL;
		char prompt[128];
		int plen = curdir_len;
		char *ppath = curdir;
		int plim = (int)(sizeof(prompt)/2)-8;
		if (plen > plim) {
			ppath = curdir + (plen - plim);
			plen = plim;
		}
		snprintf(prompt, 128, FG_BLACK BG_LIGHT_GRAY "afc:" COLOR_RESET FG_BRIGHT_YELLOW BG_BLUE "%.*s" COLOR_RESET " > ", plen, ppath);
#ifdef HAVE_READLINE
		char* cmd = readline(prompt);
		if (!cmd || !*cmd) {
			free(cmd);
			continue;
		}
		add_history(cmd);
		parse_cmdline(&argc, &argv, cmd);
#else
		char cmdbuf[4096];
		printf("%s", prompt);
		fflush(stdout);
		get_input(cmdbuf, sizeof(cmdbuf));
		parse_cmdline(&argc, &argv, cmdbuf);
#endif
#ifdef HAVE_READLINE
		free(cmd);
#endif
		/* process arguments */
		if (argv && argv[0]) {
			if (process_args(afc, argc, argv) < 0) {
				break;
			}
		}
	}
}

static void device_event_cb(const idevice_event_t* event, void* userdata)
{
	if (use_network && event->conn_type != CONNECTION_NETWORK) {
		return;
	} else if (!use_network && event->conn_type != CONNECTION_USBMUXD) {
		return;
	}
	if (event->event == IDEVICE_DEVICE_ADD) {
		if (!udid) {
			udid = strdup(event->udid);
		}
		if (strcmp(udid, event->udid) == 0) {
			connected = 1;
		}
	} else if (event->event == IDEVICE_DEVICE_REMOVE) {
		if (strcmp(udid, event->udid) == 0) {
			connected = 0;
			printf("\n[disconnected]\n");
			handle_signal(SIGINT);
		}
	}
}

int main(int argc, char** argv)
{
	const char* appid = NULL;
	int ret = 0;
	idevice_t device = NULL;
	lockdownd_client_t lockdown = NULL;
	lockdownd_error_t ldret = LOCKDOWN_E_UNKNOWN_ERROR;
	lockdownd_service_descriptor_t service = NULL;
	afc_client_t afc = NULL;
	house_arrest_client_t house_arrest = NULL;
	const char* service_name = AFC_SERVICE_NAME;
	int use_container = 0;

	int c = 0;
	const struct option longopts[] = {
		{ "udid", required_argument, NULL, 'u' },
		{ "network", no_argument, NULL, 'n' },
		{ "help", no_argument, NULL, 'h' },
		{ "debug", no_argument, NULL, 'd' },
		{ "version", no_argument, NULL, 'v' },
		{ "documents", required_argument, NULL, OPT_DOCUMENTS },
		{ "container", required_argument, NULL, OPT_CONTAINER },
		{ NULL, 0, NULL, 0}
	};

	signal(SIGTERM, handle_signal);
#ifndef _WIN32
	signal(SIGQUIT, handle_signal);
	signal(SIGPIPE, SIG_IGN);
#endif

	while ((c = getopt_long(argc, argv, "du:nhv", longopts, NULL)) != -1) {
		switch (c) {
		case 'd':
			idevice_set_debug_level(1);
			break;
		case 'u':
			if (!*optarg) {
				fprintf(stderr, "ERROR: UDID must not be empty!\n");
				print_usage(argc, argv, 1);
				return 2;
			}
			udid = strdup(optarg);
			break;
		case 'n':
			use_network = 1;
			break;
		case 'h':
			print_usage(argc, argv, 0);
			return 0;
		case 'v':
			printf("%s %s", TOOL_NAME, PACKAGE_VERSION);
#ifdef HAVE_READLINE
			printf(" (readline)");
#endif
			printf("\n");
			return 0;
		case OPT_DOCUMENTS:
			if (!*optarg) {
				fprintf(stderr, "ERROR: '--documents' requires a non-empty app ID!\n");
				print_usage(argc, argv, 1);
				return 2;
			}
			appid = optarg;
			use_container = 0;
			break;
		case OPT_CONTAINER:
			if (!*optarg) {
				fprintf(stderr, "ERROR: '--container' requires a not-empty app ID!\n");
				print_usage(argc, argv, 1);
				return 2;
			}
			appid = optarg;
			use_container = 1;
			break;
		default:
			print_usage(argc, argv, 1);
			return 2;
		}
	}

	argc -= optind;
	argv += optind;

	int num = 0;
	idevice_info_t *devices = NULL;
	idevice_get_device_list_extended(&devices, &num);
	int count = 0;
	for (int i = 0; i < num; i++) {
		if (devices[i]->conn_type == CONNECTION_NETWORK && use_network) {
			count++;
		} else if (devices[i]->conn_type == CONNECTION_USBMUXD) {
			count++;
		}
	}
	idevice_device_list_extended_free(devices);
	if (count == 0) {
		fprintf(stderr, "No device found. Plug in a device or pass UDID with -u to wait for device to be available.\n");
		return 1;
	}

	idevice_events_subscribe(&context, device_event_cb, NULL);

	while (!connected && !stop_requested) {
#ifdef _WIN32
		Sleep(100);
#else
		usleep(100000);
#endif
	}
	if (stop_requested) {
		return 0;
	}

	ret = idevice_new_with_options(&device, udid, (use_network) ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX);
	if (ret != IDEVICE_E_SUCCESS) {
		if (udid) {
			fprintf(stderr, "ERROR: Device %s not found!\n", udid);
		} else {
			fprintf(stderr, "ERROR: No device found!\n");
		}
		return 1;
	}

	do {
		if (LOCKDOWN_E_SUCCESS != (ldret = lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME))) {
			fprintf(stderr, "ERROR: Could not connect to lockdownd: %s (%d)\n", lockdownd_strerror(ldret), ldret);
			ret = 1;
			break;
		}

		if (appid) {
			service_name = HOUSE_ARREST_SERVICE_NAME;
		}

		ldret = lockdownd_start_service(lockdown, service_name, &service);
		if (ldret != LOCKDOWN_E_SUCCESS) {
			fprintf(stderr, "ERROR: Failed to start service %s: %s (%d)\n", service_name, lockdownd_strerror(ldret), ldret);
			ret = 1;
			break;
		}

		if (appid) {
			house_arrest_client_new(device, service, &house_arrest);
			if (!house_arrest) {
				fprintf(stderr, "Could not start document sharing service!\n");
				ret = 1;
				break;
			}

			if (house_arrest_send_command(house_arrest, use_container ? "VendContainer": "VendDocuments", appid) != HOUSE_ARREST_E_SUCCESS) {
				fprintf(stderr, "Could not send house_arrest command!\n");
				ret = 1;
				break;
			}

			plist_t dict = NULL;
			if (house_arrest_get_result(house_arrest, &dict) != HOUSE_ARREST_E_SUCCESS) {
				fprintf(stderr, "Could not get result from document sharing service!\n");
				break;
			}
			plist_t node = plist_dict_get_item(dict, "Error");
			if (node) {
				char *str = NULL;
				plist_get_string_val(node, &str);
				fprintf(stderr, "ERROR: %s\n", str);
				if (str && !strcmp(str, "InstallationLookupFailed")) {
					fprintf(stderr, "The App '%s' is either not present on the device, or the 'UIFileSharingEnabled' key is not set in its Info.plist. Starting with iOS 8.3 this key is mandatory to allow access to an app's Documents folder.\n", appid);
				}
				free(str);
				plist_free(dict);
				break;
			}
			plist_free(dict);
			afc_client_new_from_house_arrest_client(house_arrest, &afc);
		} else {
			afc_client_new(device, service, &afc);
		}
		lockdownd_service_descriptor_free(service);
		lockdownd_client_free(lockdown);
		lockdown = NULL;

		curdir = strdup("/");
		curdir_len = 1;

		if (argc > 0) {
			// command line mode
			process_args(afc, argc, argv);
		} else {
			// interactive mode
			start_cmdline(afc);
		}

	} while (0);

	if (afc) {
		afc_client_free(afc);
	}
	if (lockdown) {
		lockdownd_client_free(lockdown);
	}
	idevice_free(device);

	return ret;
}
