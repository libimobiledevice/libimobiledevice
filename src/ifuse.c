/* 
 * ifuse.c
 * A Fuse filesystem which exposes the iPhone's filesystem.
 *
 * Copyright (c) 2008 Matt Colyer All Rights Reserved.
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

#define FUSE_USE_VERSION  26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <usb.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <glib.h>

#include "usbmux.h"
#include "iphone.h"
#include "plist.h"
#include "lockdown.h"
#include "AFC.h"
#include "userpref.h"

GHashTable *file_handles;
int fh_index = 0;

int debug = 0;

static int ifuse_getattr(const char *path, struct stat *stbuf) {
	int res = 0;
	AFCFile *file;
	AFClient *afc = fuse_get_context()->private_data;

	memset(stbuf, 0, sizeof(struct stat));
	file = afc_get_file_info(afc, path);
	if (!file){
		res = -ENOENT;
		return res;
	}

	stbuf->st_mode = file->type | 0444;
	stbuf->st_size = file->size;
	//stbuf->st_nlink = 2;

	return res;
}

static int ifuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi) {
	int i;
	char **dirs, **filename;
	AFClient *afc = fuse_get_context()->private_data;

	dirs = afc_get_dir_list(afc, path);
	for (i = 0; strcmp(dirs[i], ""); i++) {
		filler(buf, dirs[i], NULL, 0);
	}
	
	free_dictionary(dirs);

	return 0;
}

static int ifuse_open(const char *path, struct fuse_file_info *fi) {
	AFCFile *file;
	AFClient *afc = fuse_get_context()->private_data;

	if((fi->flags & 3) != O_RDONLY)
		return -EACCES;
	
	file = afc_open_file(afc, path, AFC_FILE_READ);
	
	fh_index++;
	fi->fh = fh_index;
	g_hash_table_insert(file_handles, &fh_index, file);

	return 0;
}

static int ifuse_read(const char *path, char *buf, size_t size, off_t offset,
			struct fuse_file_info *fi) {
	int bytes;
	AFCFile *file;
	AFClient *afc = fuse_get_context()->private_data;

	file = g_hash_table_lookup(file_handles, &(fi->fh));
	if (!file){
		return -ENOENT;
	}

	bytes = afc_read_file(afc, file, buf, size);

	return bytes;
}

void *ifuse_init(struct fuse_conn_info *conn) {
	char *response = (char*)malloc(sizeof(char) * 2048);
	int bytes = 0, port = 0, i = 0;
	char* host_id = NULL;
	AFClient *afc = NULL;
	
	conn->async_read = 0;

	file_handles = g_hash_table_new(g_int_hash, g_int_equal);

	iPhone *phone = get_iPhone();
	if (!phone){
		fprintf(stderr, "No iPhone found, is it connected?\n");
		   	return NULL;
	   	}
	
	lockdownd_client *control = new_lockdownd_client(phone);
	if (!lockdownd_hello(control)) {
		fprintf(stderr, "Something went wrong in the lockdownd client.\n");
		return NULL;
	}

	host_id = get_host_id();
	if (host_id && !lockdownd_start_SSL_session(control, host_id) || !host_id) {
		fprintf(stderr, "Something went wrong in GnuTLS. Is your HostID configured in .config/libiphone/libiphonerc?\n");
		return NULL;
	}
	free(host_id);
	host_id = NULL;
	
	port = lockdownd_start_service(control, "com.apple.afc");
	if (!port) {
		fprintf(stderr, "Something went wrong when starting AFC.");
                return NULL;
	}

	afc = afc_connect(phone, 3432, port);

        return afc;
}

void ifuse_cleanup(AFClient *afc) {
	if (afc) {
		free_iPhone(afc->phone);
		afc_disconnect(afc);
	}
}

static struct fuse_operations ifuse_oper = {
	.getattr	= ifuse_getattr,
	.readdir	= ifuse_readdir,
	.open		= ifuse_open,
	.read		= ifuse_read,
	.init		= ifuse_init,
	.destroy	= ifuse_cleanup
};

int main(int argc, char *argv[]) {
	return fuse_main(argc, argv, &ifuse_oper, NULL);
}
