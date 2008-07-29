
#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>


#ifndef USBMUX_H
#define USBMUX_H

#ifndef IPHONE_H
#include "iphone.h"
#endif

typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint8_t uint8;


typedef struct {
	uint32 type, length;
	uint16 sport, dport;
	uint32 scnt, ocnt;
	uint8 offset, tcp_flags;
	uint16 window, nullnull, length16;
} usbmux_tcp_header;

usbmux_tcp_header *new_mux_packet(uint16 s_port, uint16 d_port);

typedef struct {
	uint32 type, length, major, minor, allnull;
} usbmux_version_header;

usbmux_version_header *version_header();

usbmux_tcp_header *mux_connect(iPhone *phone, uint16 s_port, uint16 d_port);
void mux_close_connection(iPhone *phone, usbmux_tcp_header *connection);
int mux_send(iPhone *phone, usbmux_tcp_header *connection, char *data, uint32 datalen);
int mux_recv(iPhone *phone, usbmux_tcp_header *connection, char *data, uint32 datalen);
#endif
