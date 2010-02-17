#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/screenshotr.h>

void print_usage(int argc, char **argv);

int main(int argc, char **argv)
{
	idevice_t device = NULL;
	lockdownd_client_t lckd = NULL;
	screenshotr_client_t shotr = NULL;
	uint16_t port = 0;
	int result = -1;
	int i;
	char *uuid = NULL;

	/* parse cmdline args */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
			idevice_set_debug_level(1);
			continue;
		}
		else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--uuid")) {
			i++;
			if (!argv[i] || (strlen(argv[i]) != 40)) {
				print_usage(argc, argv);
				return 0;
			}
			uuid = strdup(argv[i]);
			continue;
		}
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
			return 0;
		}
		else {
			print_usage(argc, argv);
			return 0;
		}
	}

	if (IDEVICE_E_SUCCESS != idevice_new(&device, uuid)) {
		printf("No device found, is it plugged in?\n");
		if (uuid) {
			free(uuid);
		}
		return -1;
	}
	if (uuid) {
		free(uuid);
	}

	if (LOCKDOWN_E_SUCCESS != lockdownd_client_new_with_handshake(device, &lckd, NULL)) {
		idevice_free(device);
		printf("Exiting.\n");
		return -1;
	}

	lockdownd_start_service(lckd, "com.apple.mobile.screenshotr", &port);
	lockdownd_client_free(lckd);
	if (port > 0) {
		if (screenshotr_client_new(device, port, &shotr) != SCREENSHOTR_E_SUCCESS) {
			printf("Could not connect to screenshotr!\n");
		} else {
			char *imgdata = NULL;
			uint64_t imgsize = 0;
			if (screenshotr_take_screenshot(shotr, &imgdata, &imgsize) == SCREENSHOTR_E_SUCCESS) {
				FILE *f = fopen("screenshot.tiff", "w");
				if (f) {
					if (fwrite(imgdata, 1, (size_t)imgsize, f) == (size_t)imgsize) {
						printf("Screenshot saved to screenshot.tiff\n");
						result = 0;
					} else {
						printf("Could not save screenshot to file!\n");
					}
					fclose(f);
				} else {
					printf("Could not open screenshot.tiff for writing: %s\n", strerror(errno));
				}
			} else {
				printf("Could not get screenshot!\n");
			}
			screenshotr_client_free(shotr);
		}
	} else {
		printf("Could not start screenshotr service! Remember that you have to mount the Developer disk image on your device if you want to use the screenshotr service.\n");
	}
	idevice_free(device);
	
	return result;
}

void print_usage(int argc, char **argv)
{
        char *name = NULL;

        name = strrchr(argv[0], '/');
        printf("Usage: %s [OPTIONS]\n", (name ? name + 1: argv[0]));
        printf("Gets a screenshot from the connected iPhone/iPod Touch.\n");
	printf("NOTE: A mounted developer disk image is required on the device, otherwise\n");
	printf(" the screenshotr service is not available.\n\n");
        printf("  -d, --debug\t\tenable communication debugging\n");
        printf("  -u, --uuid UUID\ttarget specific device by its 40-digit device UUID\n");
        printf("  -h, --help\t\tprints usage information\n");
        printf("\n");
}
