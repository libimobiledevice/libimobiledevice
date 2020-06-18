/*
 * idevicesyslog.c
 * Relay the syslog of a device to stdout
 *
 * Copyright (c) 2010-2020 Nikias Bassen, All Rights Reserved.
 * Copyright (c) 2009 Martin Szulecki All Rights Reserved.
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
#include "config.h"
#endif

#define TOOL_NAME "idevicesyslog"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#ifdef WIN32
#include <windows.h>
#define sleep(x) Sleep(x*1000)
#endif

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/syslog_relay.h>

static int quit_flag = 0;
static int exit_on_disconnect = 0;
static int use_colors = 0;
static int show_device_name = 0;

static char* udid = NULL;
static char** proc_filters = NULL;
static int num_proc_filters = 0;
static int proc_filter_excluding = 0;

static int* pid_filters = NULL;
static int num_pid_filters = 0;

static char** msg_filters = NULL;
static int num_msg_filters = 0;

static char** trigger_filters = NULL;
static int num_trigger_filters = 0;
static char** untrigger_filters = NULL;
static int num_untrigger_filters = 0;
static int triggered = 0;

static idevice_t device = NULL;
static syslog_relay_client_t syslog = NULL;

static const char QUIET_FILTER[] = "CircleJoinRequested|CommCenter|HeuristicInterpreter|MobileMail|PowerUIAgent|ProtectedCloudKeySyncing|SpringBoard|UserEventAgent|WirelessRadioManagerd|accessoryd|accountsd|aggregated|analyticsd|appstored|apsd|assetsd|assistant_service|backboardd|biometrickitd|bluetoothd|calaccessd|callservicesd|cloudd|com.apple.Safari.SafeBrowsing.Service|contextstored|corecaptured|coreduetd|corespeechd|cdpd|dasd|dataaccessd|distnoted|dprivacyd|duetexpertd|findmydeviced|fmfd|fmflocatord|gpsd|healthd|homed|identityservicesd|imagent|itunescloudd|itunesstored|kernel|locationd|maild|mDNSResponder|mediaremoted|mediaserverd|mobileassetd|nanoregistryd|nanotimekitcompaniond|navd|nsurlsessiond|passd|pasted|photoanalysisd|powerd|powerlogHelperd|ptpd|rapportd|remindd|routined|runningboardd|searchd|sharingd|suggestd|symptomsd|timed|thermalmonitord|useractivityd|vmd|wifid|wirelessproxd";

static int use_network = 0;

static char *line = NULL;
static int line_buffer_size = 0;
static int lp = 0;

#ifdef WIN32
static WORD COLOR_RESET = 0;
static HANDLE h_stdout = INVALID_HANDLE_VALUE;

#define COLOR_NORMAL        COLOR_RESET
#define COLOR_DARK          FOREGROUND_INTENSITY
#define COLOR_RED           FOREGROUND_RED |FOREGROUND_INTENSITY
#define COLOR_DARK_RED      FOREGROUND_RED
#define COLOR_GREEN         FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define COLOR_DARK_GREEN    FOREGROUND_GREEN
#define COLOR_YELLOW        FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY
#define COLOR_DARK_YELLOW   FOREGROUND_GREEN | FOREGROUND_RED
#define COLOR_BLUE          FOREGROUND_BLUE | FOREGROUND_INTENSITY
#define COLOR_DARK_BLUE     FOREGROUND_BLUE
#define COLOR_MAGENTA       FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY
#define COLOR_DARK_MAGENTA  FOREGROUND_BLUE | FOREGROUND_RED
#define COLOR_CYAN          FOREGROUND_BLUE | FOREGROUND_GREEN
#define COLOR_BRIGHT_CYAN   FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define COLOR_DARK_CYAN     FOREGROUND_BLUE | FOREGROUND_GREEN
#define COLOR_WHITE         FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY
#define COLOR_DARK_WHITE    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE

static void TEXT_COLOR(WORD attr)
{
	if (use_colors) {
		SetConsoleTextAttribute(h_stdout, attr);
	}
}
#else

#define COLOR_RESET         "\e[m"
#define COLOR_NORMAL        "\e[0m"
#define COLOR_DARK          "\e[2m"
#define COLOR_RED           "\e[0;31m"
#define COLOR_DARK_RED      "\e[2;31m"
#define COLOR_GREEN         "\e[0;32m"
#define COLOR_DARK_GREEN    "\e[2;32m"
#define COLOR_YELLOW        "\e[0;33m"
#define COLOR_DARK_YELLOW   "\e[2;33m"
#define COLOR_BLUE          "\e[0;34m"
#define COLOR_DARK_BLUE     "\e[2;34m"
#define COLOR_MAGENTA       "\e[0;35m"
#define COLOR_DARK_MAGENTA  "\e[2;35m"
#define COLOR_CYAN          "\e[0;36m"
#define COLOR_BRIGHT_CYAN   "\e[1;36m"
#define COLOR_DARK_CYAN     "\e[2;36m"
#define COLOR_WHITE         "\e[1;37m"
#define COLOR_DARK_WHITE    "\e[0;37m"

#define TEXT_COLOR(x) if (use_colors) { fwrite(x, 1, sizeof(x)-1, stdout); }
#endif

static void add_filter(const char* filterstr)
{
	int filter_len = strlen(filterstr);
	const char* start = filterstr;
	const char* end = filterstr + filter_len;
	const char* p = start;
	while (p <= end) {
		if ((*p == '|') || (*p == '\0')) {
			if (p-start > 0) {
				char* procn = malloc(p-start+1);
				if (!procn) {
					fprintf(stderr, "ERROR: malloc() failed\n");
					exit(EXIT_FAILURE);
				}
				memcpy(procn, start, p-start);
				procn[p-start] = '\0';
				char* endp = NULL;
				int pid_value = (int)strtol(procn, &endp, 10);
				if (!endp || *endp == 0) {
					int *new_pid_filters = realloc(pid_filters, sizeof(int) * (num_pid_filters+1));
					if (!new_pid_filters) {
						fprintf(stderr, "ERROR: realloc() failed\n");
						exit(EXIT_FAILURE);
					}
					pid_filters = new_pid_filters;
					pid_filters[num_pid_filters] = pid_value;
					num_pid_filters++;
				} else {
					char **new_proc_filters = realloc(proc_filters, sizeof(char*) * (num_proc_filters+1));
					if (!new_proc_filters) {
						fprintf(stderr, "ERROR: realloc() failed\n");
						exit(EXIT_FAILURE);
					}
					proc_filters = new_proc_filters;
					proc_filters[num_proc_filters] = procn;
					num_proc_filters++;
				}
			}
			start = p+1;
		}
		p++;
	}
}

static int find_char(char c, char** p, char* end)
{
	while ((**p != c) && (*p < end)) {
		(*p)++;
	}
	return (**p == c);
}

static void stop_logging(void);

static void syslog_callback(char c, void *user_data)
{
	if (lp >= line_buffer_size-1) {
		line_buffer_size+=1024;
		char* _line = realloc(line, line_buffer_size);
		if (!_line) {
			fprintf(stderr, "ERROR: realloc failed\n");
			exit(EXIT_FAILURE);
		}
		line = _line;
	}
	line[lp++] = c;
	if (c == '\0') {
		int shall_print = 0;
		int trigger_off = 0;
		lp--;
		char* linep = &line[0];
		do {
			if (lp < 16) {
				shall_print = 1;
				TEXT_COLOR(COLOR_WHITE);
				break;
			} else if (line[3] == ' ' && line[6] == ' ' && line[15] == ' ') {
				char* end = &line[lp];
				char* p = &line[16];

				/* device name */
				char* device_name_start = p;
				char* device_name_end = p;
				if (!find_char(' ', &p, end)) break;
				device_name_end = p;
				p++;

				/* check if we have any triggers/untriggers */
				if (num_untrigger_filters > 0 && triggered) {
					int found = 0;
					int i;
					for (i = 0; i < num_untrigger_filters; i++) {
						if (strstr(device_name_end+1, untrigger_filters[i])) {
							found = 1;
							break;
						}
					}
					if (!found) {
						shall_print = 1;
					} else {
						shall_print = 1;
						trigger_off = 1;
					}
				} else if (num_trigger_filters > 0 && !triggered) {
					int found = 0;
					int i;
					for (i = 0; i < num_trigger_filters; i++) {
						if (strstr(device_name_end+1, trigger_filters[i])) {
							found = 1;
							break;
						}
					}
					if (!found) {
						shall_print = 0;
						break;
					} else {
						triggered = 1;
						shall_print = 1;
					}
				} else if (num_trigger_filters == 0 && num_untrigger_filters > 0 && !triggered) {
					shall_print = 0;
					quit_flag++;
					break;
				}

				/* check message filters */
				if (num_msg_filters > 0) {
					int found = 0;
					int i;
					for (i = 0; i < num_msg_filters; i++) {
						if (strstr(device_name_end+1, msg_filters[i])) {
							found = 1;
							break;
						}
					}
					if (!found) {
						shall_print = 0;
						break;
					} else {
						shall_print = 1;
					}
				}

				/* process name */
				char* proc_name_start = p;
				char* proc_name_end = p;
				if (!find_char('[', &p, end)) break;
				char* process_name_start = proc_name_start;
				char* process_name_end = p;
				char* pid_start = p+1;
				char* pp = process_name_start;
				if (find_char('(', &pp, p)) {
					process_name_end = pp;
				}
				if (!find_char(']', &p, end)) break;
				p++;
				if (*p != ' ') break;
				proc_name_end = p;
				p++;

				int proc_matched = 0;
				if (num_pid_filters > 0) {
					char* endp = NULL;
					int pid_value = (int)strtol(pid_start, &endp, 10);
					if (endp && (*endp == ']')) {
						int found = proc_filter_excluding;
						int i = 0;
						for (i = 0; i < num_pid_filters; i++) {
							if (pid_value == pid_filters[i]) {
								found = !proc_filter_excluding;
								break;
							}
						}
						if (found) {
							proc_matched = 1;
						}
					}
				}
				if (num_proc_filters > 0 && !proc_matched) {
					int found = proc_filter_excluding;
					int i = 0;
					for (i = 0; i < num_proc_filters; i++) {
						if (!proc_filters[i]) continue;
						if (strncmp(proc_filters[i], process_name_start, process_name_end-process_name_start) == 0) {
							found = !proc_filter_excluding;
							break;
						}
					}
					if (found) {
						proc_matched = 1;
					}
				}
				if (proc_matched) {
					shall_print = 1;
				} else {
					if (num_pid_filters > 0 || num_proc_filters > 0) {
						shall_print = 0;
						break;
					}
				}

				/* log level */
				char* level_start = p;
				char* level_end = p;
#ifdef WIN32
				WORD level_color = COLOR_NORMAL;
#else
				const char* level_color = NULL;
#endif
				if (!strncmp(p, "<Notice>:", 9)) {
					level_end += 9;
					level_color = COLOR_GREEN;
				} else if (!strncmp(p, "<Error>:", 8)) {
					level_end += 8;
					level_color = COLOR_RED;
				} else if (!strncmp(p, "<Warning>:", 10)) {
					level_end += 10;
					level_color = COLOR_YELLOW;
				} else if (!strncmp(p, "<Debug>:", 8)) {
					level_end += 8;
					level_color = COLOR_MAGENTA;
				} else {
					level_color = COLOR_WHITE;
				}

				/* write date and time */
				TEXT_COLOR(COLOR_DARK_WHITE);
				fwrite(line, 1, 16, stdout);

				if (show_device_name) {
					/* write device name */
					TEXT_COLOR(COLOR_DARK_YELLOW);
					fwrite(device_name_start, 1, device_name_end-device_name_start+1, stdout);
					TEXT_COLOR(COLOR_RESET);
				}

				/* write process name */
				TEXT_COLOR(COLOR_BRIGHT_CYAN);
				fwrite(process_name_start, 1, process_name_end-process_name_start, stdout);
				TEXT_COLOR(COLOR_CYAN);
				fwrite(process_name_end, 1, proc_name_end-process_name_end+1, stdout);

				/* write log level */
				TEXT_COLOR(level_color);
				if (level_end > level_start) {
					fwrite(level_start, 1, level_end-level_start, stdout);
					p = level_end;
				}

				lp -= p - linep;
				linep = p;

				TEXT_COLOR(COLOR_WHITE);

			} else {
				shall_print = 1;
				TEXT_COLOR(COLOR_WHITE);
			}
		} while (0);

		if ((num_msg_filters == 0 && num_proc_filters == 0 && num_pid_filters == 0 && num_trigger_filters == 0 && num_untrigger_filters == 0) || shall_print) {
			fwrite(linep, 1, lp, stdout);
			TEXT_COLOR(COLOR_RESET);
			fflush(stdout);
			if (trigger_off) {
				triggered = 0;
			}
		}
		line[0] = '\0';
		lp = 0;
		return;
	}
}

static int start_logging(void)
{
	idevice_error_t ret = idevice_new_with_options(&device, udid, (use_network) ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX);
	if (ret != IDEVICE_E_SUCCESS) {
		fprintf(stderr, "Device with udid %s not found!?\n", udid);
		return -1;
	}

	lockdownd_client_t lockdown = NULL;
	lockdownd_error_t lerr = lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME);
	if (lerr != LOCKDOWN_E_SUCCESS) {
		fprintf(stderr, "ERROR: Could not connect to lockdownd: %d\n", lerr);
		idevice_free(device);
		device = NULL;
		return -1;
	}

	/* start syslog_relay service */
	lockdownd_service_descriptor_t svc = NULL;
	lerr = lockdownd_start_service(lockdown, SYSLOG_RELAY_SERVICE_NAME, &svc);
	if (lerr == LOCKDOWN_E_PASSWORD_PROTECTED) {
		fprintf(stderr, "*** Device is passcode protected, enter passcode on the device to continue ***\n");
		while (!quit_flag) {
			lerr = lockdownd_start_service(lockdown, SYSLOG_RELAY_SERVICE_NAME, &svc);
			if (lerr != LOCKDOWN_E_PASSWORD_PROTECTED) {
				break;
			}
			sleep(1);
		}
	}
	if (lerr != LOCKDOWN_E_SUCCESS) {
		fprintf(stderr, "ERROR: Could not connect to lockdownd: %d\n", lerr);
		idevice_free(device);
		device = NULL;
		return -1;
	}
	lockdownd_client_free(lockdown);

	/* connect to syslog_relay service */
	syslog_relay_error_t serr = SYSLOG_RELAY_E_UNKNOWN_ERROR;
	serr = syslog_relay_client_new(device, svc, &syslog);
	lockdownd_service_descriptor_free(svc);
	if (serr != SYSLOG_RELAY_E_SUCCESS) {
		fprintf(stderr, "ERROR: Could not start service com.apple.syslog_relay.\n");
		idevice_free(device);
		device = NULL;
		return -1;
	}

	/* start capturing syslog */
	serr = syslog_relay_start_capture_raw(syslog, syslog_callback, NULL);
	if (serr != SYSLOG_RELAY_E_SUCCESS) {
		fprintf(stderr, "ERROR: Unable tot start capturing syslog.\n");
		syslog_relay_client_free(syslog);
		syslog = NULL;
		idevice_free(device);
		device = NULL;
		return -1;
	}

	fprintf(stdout, "[connected:%s]\n", udid);
	fflush(stdout);

	return 0;
}

static void stop_logging(void)
{
	fflush(stdout);

	if (syslog) {
		syslog_relay_client_free(syslog);
		syslog = NULL;
	}

	if (device) {
		idevice_free(device);
		device = NULL;
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
		if (!syslog) {
			if (!udid) {
				udid = strdup(event->udid);
			}
			if (strcmp(udid, event->udid) == 0) {
				if (start_logging() != 0) {
					fprintf(stderr, "Could not start logger for udid %s\n", udid);
				}
			}
		}
	} else if (event->event == IDEVICE_DEVICE_REMOVE) {
		if (syslog && (strcmp(udid, event->udid) == 0)) {
			stop_logging();
			fprintf(stdout, "[disconnected:%s]\n", udid);
			if (exit_on_disconnect) {
				quit_flag++;
			}
		}
	}
}

/**
 * signal handler function for cleaning up properly
 */
static void clean_exit(int sig)
{
	fprintf(stderr, "\nExiting...\n");
	quit_flag++;
}

static void print_usage(int argc, char **argv, int is_error)
{
	char *name = NULL;
	name = strrchr(argv[0], '/');
	fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS]\n", (name ? name + 1: argv[0]));
	fprintf(is_error ? stderr : stdout,
		"\n" \
		"Relay syslog of a connected device.\n" \
		"\n" \
		"OPTIONS:\n" \
		"  -u, --udid UDID  target specific device by UDID\n" \
		"  -n, --network    connect to network device\n" \
		"  -x, --exit       exit when device disconnects\n" \
		"  -h, --help       prints usage information\n" \
		"  -d, --debug      enable communication debugging\n" \
		"  -v, --version    prints version information\n" \
		" --no-colors       disable colored output\n" \
		"\n" \
		"FILTER OPTIONS:\n" \
		"  -m, --match STRING      only print messages that contain STRING\n" \
		"  -t, --trigger STRING    start logging when matching STRING\n" \
		"  -T, --untrigger STRING  stop logging when matching STRING\n" \
		"  -p, --process PROCESS   only print messages from matching process(es)\n" \
		"  -e, --exclude PROCESS   print all messages except matching process(es)\n" \
		"                          PROCESS is a process name or multiple process names\n" \
		"                          separated by \"|\".\n" \
		"  -q, --quiet             set a filter to exclude common noisy processes\n" \
		"  --quiet-list            prints the list of processes for --quiet and exits\n" \
		"  -k, --kernel            only print kernel messages\n" \
		"  -K, --no-kernel         suppress kernel messages\n" \
		"\n" \
		"For filter examples consult idevicesyslog(1) man page.\n" \
		"\n" \
		"Homepage:    <" PACKAGE_URL ">\n"
		"Bug Reports: <" PACKAGE_BUGREPORT ">\n"
	);
}

int main(int argc, char *argv[])
{
#ifdef WIN32
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
	if (GetConsoleScreenBufferInfo(h_stdout, &csbi)) {
		COLOR_RESET = csbi.wAttributes;
	}
#endif
	int no_colors = 0;
	int include_filter = 0;
	int exclude_filter = 0;
	int include_kernel = 0;
	int exclude_kernel = 0;
	int c = 0;
	const struct option longopts[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "udid", required_argument, NULL, 'u' },
		{ "network", no_argument, NULL, 'n' },
		{ "exit", no_argument, NULL, 'x' },
		{ "trigger", required_argument, NULL, 't' },
		{ "untrigger", required_argument, NULL, 'T' },
		{ "match", required_argument, NULL, 'm' },
		{ "process", required_argument, NULL, 'p' },
		{ "exclude", required_argument, NULL, 'e' },
		{ "quiet", no_argument, NULL, 'q' },
		{ "kernel", no_argument, NULL, 'k' },
		{ "no-kernel", no_argument, NULL, 'K' },
		{ "quiet-list", no_argument, NULL, 1 },
		{ "no-colors", no_argument, NULL, 2 },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0}
	};

	signal(SIGINT, clean_exit);
	signal(SIGTERM, clean_exit);
#ifndef WIN32
	signal(SIGQUIT, clean_exit);
	signal(SIGPIPE, SIG_IGN);
#endif

	while ((c = getopt_long(argc, argv, "dhu:nxt:T:m:e:p:qkKv", longopts, NULL)) != -1) {
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
			free(udid);
			udid = strdup(optarg);
			break;
		case 'n':
			use_network = 1;
			break;
		case 'q':
			exclude_filter++;
			add_filter(QUIET_FILTER);
			break;
		case 'p':
		case 'e':
			if (c == 'p') {
				include_filter++;
			} else if (c == 'e') {
				exclude_filter++;
			}
			if (!*optarg) {
				fprintf(stderr, "ERROR: filter string must not be empty!\n");
				print_usage(argc, argv, 1);
				return 2;
			}
			add_filter(optarg);
			break;
		case 'm':
			if (!*optarg) {
				fprintf(stderr, "ERROR: message filter string must not be empty!\n");
				print_usage(argc, argv, 1);
				return 2;
			} else {
				char **new_msg_filters = realloc(msg_filters, sizeof(char*) * (num_msg_filters+1));
				if (!new_msg_filters) {
					fprintf(stderr, "ERROR: realloc() failed\n");
					exit(EXIT_FAILURE);
				}
				msg_filters = new_msg_filters;
				msg_filters[num_msg_filters] = strdup(optarg);
				num_msg_filters++;
			}
			break;
		case 't':
			if (!*optarg) {
				fprintf(stderr, "ERROR: trigger filter string must not be empty!\n");
				print_usage(argc, argv, 1);
				return 2;
			} else {
				char **new_trigger_filters = realloc(trigger_filters, sizeof(char*) * (num_trigger_filters+1));
				if (!new_trigger_filters) {
					fprintf(stderr, "ERROR: realloc() failed\n");
					exit(EXIT_FAILURE);
				}
				trigger_filters = new_trigger_filters;
				trigger_filters[num_trigger_filters] = strdup(optarg);
				num_trigger_filters++;
			}
			break;
		case 'T':
			if (!*optarg) {
				fprintf(stderr, "ERROR: untrigger filter string must not be empty!\n");
				print_usage(argc, argv, 1);
				return 2;
			} else {
				char **new_untrigger_filters = realloc(untrigger_filters, sizeof(char*) * (num_untrigger_filters+1));
				if (!new_untrigger_filters) {
					fprintf(stderr, "ERROR: realloc() failed\n");
					exit(EXIT_FAILURE);
				}
				untrigger_filters = new_untrigger_filters;
				untrigger_filters[num_untrigger_filters] = strdup(optarg);
				num_untrigger_filters++;
			}
			break;
		case 'k':
			include_kernel++;
			break;
		case 'K':
			exclude_kernel++;
			break;
		case 'x':
			exit_on_disconnect = 1;
			break;
		case 'h':
			print_usage(argc, argv, 0);
			return 0;
		case 1:	{
			printf("%s\n", QUIET_FILTER);
			return 0;
		}
		case 2:
			no_colors = 1;
			break;
		case 'v':
			printf("%s %s\n", TOOL_NAME, PACKAGE_VERSION);
			return 0;
		default:
			print_usage(argc, argv, 1);
			return 2;
		}
	}

	if (include_kernel > 0 && exclude_kernel > 0) {
		fprintf(stderr, "ERROR: -k and -K cannot be used together.\n");
		print_usage(argc, argv, 1);
		return 2;
	}

	if (include_filter > 0 && exclude_filter > 0) {
		fprintf(stderr, "ERROR: -p and -e/-q cannot be used together.\n");
		print_usage(argc, argv, 1);
		return 2;
	} else if (include_filter > 0 && exclude_kernel > 0) {
		fprintf(stderr, "ERROR: -p and -K cannot be used together.\n");
		print_usage(argc, argv, 1);
		return 2;
	}

	if (exclude_filter > 0) {
		proc_filter_excluding = 1;
		if (include_kernel) {
			int i = 0;
			for (i = 0; i < num_proc_filters; i++) {
				if (!strcmp(proc_filters[i], "kernel")) {
					free(proc_filters[i]);
					proc_filters[i] = NULL;
				}
			}
		} else if (exclude_kernel) {
			add_filter("kernel");
		}
	} else {
		if (include_kernel) {
			add_filter("kernel");
		} else if (exclude_kernel) {
			proc_filter_excluding = 1;
			add_filter("kernel");
		}
	}

	if (num_untrigger_filters > 0 && num_trigger_filters == 0) {
		triggered = 1;
	}

	argc -= optind;
	argv += optind;

	if (!no_colors && isatty(1)) {
		use_colors = 1;
	}

	int num = 0;
	idevice_info_t *devices = NULL;
	idevice_get_device_list_extended(&devices, &num);
	idevice_device_list_extended_free(devices);
	if (num == 0) {
		if (!udid) {
			fprintf(stderr, "No device found. Plug in a device or pass UDID with -u to wait for device to be available.\n");
			return -1;
		} else {
			fprintf(stderr, "Waiting for device with UDID %s to become available...\n", udid);
		}
	}

	line_buffer_size = 1024;
	line = malloc(line_buffer_size);

	idevice_event_subscribe(device_event_cb, NULL);

	while (!quit_flag) {
		sleep(1);
	}
	idevice_event_unsubscribe();
	stop_logging();

	if (num_proc_filters > 0) {
		int i;
		for (i = 0; i < num_proc_filters; i++) {
			free(proc_filters[i]);
		}
		free(proc_filters);
	}
	if (num_pid_filters > 0) {
		free(pid_filters);
	}
	if (num_msg_filters > 0) {
		int i;
		for (i = 0; i < num_msg_filters; i++) {
			free(msg_filters[i]);
		}
		free(msg_filters);
	}
	if (num_trigger_filters > 0) {
		int i;
		for (i = 0; i < num_trigger_filters; i++) {
			free(trigger_filters[i]);
		}
		free(trigger_filters);
	}
	if (num_untrigger_filters > 0) {
		int i;
		for (i = 0; i < num_untrigger_filters; i++) {
			free(untrigger_filters[i]);
		}
		free(untrigger_filters);
	}

	free(line);

	free(udid);

	return 0;
}
