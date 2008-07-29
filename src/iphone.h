/* iphone.h
 * iPhone struct
 * Written by FxChiP */

#ifndef IPHONE_H
#define IPHONE_H

#ifndef USBMUX_H 
#include "usbmux.h"
#warning usbmux not included?
#endif

#include <usb.h>

#define BULKIN 0x85
#define BULKOUT 0x04

typedef struct {
	char *buffer;
	struct usb_dev_handle *device;
	struct usb_device *__device;
} iPhone;

// Function definitions
void free_iPhone(iPhone *victim);
iPhone *get_iPhone();
int send_to_phone(iPhone *phone, char *data, int datalen);
int recv_from_phone(iPhone *phone, char *data, int datalen);
#endif
