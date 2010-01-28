#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define MODE_NONE 0
#define MODE_SHOW_ID 1
#define MODE_LIST_DEVICES 2

static void print_usage(int argc, char **argv)
{
	char *name = NULL;
	
	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] [UUID]\n", (name ? name + 1: argv[0]));
	printf("Prints device name or a list of attached iPhone/iPod Touch devices.\n\n");
	printf("  The UUID is a 40-digit hexadecimal number of the device\n");
	printf("  for which the name should be retrieved.\n\n");
	printf("  -l, --list\t\tlist UUID of all attached devices\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
}

int main(int argc, char **argv)
{
	idevice_t phone = NULL;
	lockdownd_client_t client = NULL;
	char **dev_list = NULL;
	char *devname = NULL;
	int ret = 0;
	int i;
	int mode = MODE_SHOW_ID;
	char uuid[41];
	uuid[0] = 0;

	/* parse cmdline args */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
			idevice_set_debug_level(1);
			continue;
		}
		else if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--list")) {
			mode = MODE_LIST_DEVICES;
			continue;
		}
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
			return 0;
		}
	}

	/* check if uuid was passed */
	if (mode == MODE_SHOW_ID) {
		i--;
		if (!argv[i] || (strlen(argv[i]) != 40)) {
			print_usage(argc, argv);
			return 0;
		}
		strcpy(uuid, argv[i]);
	}

	switch (mode) {
	case MODE_SHOW_ID:
		idevice_new(&phone, uuid);
		if (!phone) {
			fprintf(stderr, "ERROR: No device with UUID=%s attached.\n", uuid);
			return -2;
		}

		if (LOCKDOWN_E_SUCCESS != lockdownd_client_new(phone, &client, "idevice_id")) {
			idevice_free(phone);
			fprintf(stderr, "ERROR: Connecting to device failed!\n");
			return -2;
		}

		if ((LOCKDOWN_E_SUCCESS != lockdownd_get_device_name(client, &devname)) || !devname) {
			fprintf(stderr, "ERROR: Could not get device name!\n");
			ret = -2;
		}

		lockdownd_client_free(client);
		idevice_free(phone);

		if (ret == 0) {
			printf("%s\n", devname);
		}

		if (devname) {
			free(devname);
		}

		return ret;
	case MODE_LIST_DEVICES:
	default:
		if (idevice_get_device_list(&dev_list, &i) < 0) {
			fprintf(stderr, "ERROR: Unable to retrieve device list!\n");
			return -1;
		}
		for (i = 0; dev_list[i] != NULL; i++) {
			printf("%s\n", dev_list[i]);
		}
		idevice_device_list_free(dev_list);
		return 0;
	}
}
