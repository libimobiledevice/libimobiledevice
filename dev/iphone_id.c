#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <libiphone/libiphone.h>
#include <usbmuxd.h>

static void usage()
{
	printf("usage: iphone_id <device_uuid>\n"
		"\tdevice_uuid is the 40-digit hexadecimal UUID of the device\n"
		"\tfor which the name should be retrieved.\n\n"
		"usage: iphone_id -l\n"
		"\tList all attached devices.\n");
	exit(0);
}

int main(int argc, char **argv)
{
	iphone_device_t phone = NULL;
	iphone_lckd_client_t control = NULL;
	usbmuxd_scan_result *dev_list;
	char *devname = NULL;
	int ret = 0;
	int c;
	int i;
	int opt_list = 0;

	while ((c = getopt(argc, argv, "lh")) != -1) {
		switch (c) {
		    case 'l':
			opt_list = 1;
			break;
		    case 'h':
		    default:
			usage();
		}
	}

	if (argc < 2) {
		usage();
	}

	argc -= optind;
	argv += optind;

	if ((!opt_list) && (strlen(argv[0]) != 40)) {
		usage();
	}

	if (opt_list) {
		if (usbmuxd_scan(&dev_list) < 0) {
			fprintf(stderr, "ERROR: usbmuxd is not running!\n");
			return -1;
		}
		for (i = 0; dev_list[i].handle > 0; i++) {
			printf("handle=%d product_id=%04x uuid=%s\n", dev_list[i].handle, dev_list[i].product_id, dev_list[i].serial_number);
		}
		return 0;
	}

	iphone_set_debug(0);

	iphone_get_device_by_uuid(&phone, argv[0]);
	if (!phone) {
		fprintf(stderr, "ERROR: No device with UUID=%s attached.\n", argv[0]);
		return -2;
	}

	if (IPHONE_E_SUCCESS != iphone_lckd_new_client(phone, &control)) {
		iphone_free_device(phone);
		fprintf(stderr, "ERROR: Connecting to device failed!\n");
		return -2;
	}

	if ((IPHONE_E_SUCCESS != lockdownd_get_device_name(control, &devname)) || !devname) {
		fprintf(stderr, "ERROR: Could not get device name!\n");
		ret = -2;
	}

	iphone_lckd_free_client(control);
	iphone_free_device(phone);

	if (ret == 0) {
		printf("%s\n", devname);
	}

	if (devname) {
		free(devname);
	}

	return ret;
}
