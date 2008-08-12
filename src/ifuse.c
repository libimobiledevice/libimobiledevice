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
#include <unistd.h>

#include "usbmux.h"
#include "iphone.h"
#include "plist.h"
#include "lockdown.h"
#include "AFC.h"
#include "userpref.h"

GHashTable *file_handles;
int fh_index = 0;

iPhone *phone = NULL;
lockdownd_client *control = NULL;

int debug = 0;

static int ifuse_getattr(const char *path, struct stat *stbuf) {
	int res = 0;
	AFCFile *file;
	AFClient *afc = fuse_get_context()->private_data;

	memset(stbuf, 0, sizeof(struct stat));
	file = afc_get_file_info(afc, path);
	if (!file){
		res = -ENOENT;
	} else {
		stbuf->st_mode = file->type | 0644; // but we don't want anything on the iPhone executable, like, ever
		stbuf->st_size = file->size;
		stbuf->st_blksize = 2048; // FIXME: Is this the actual block size used on the iPhone?
		stbuf->st_blocks = file->blocks;
		stbuf->st_uid = getuid();
		stbuf->st_gid = getgid();

		afc_close_file(afc,file);
		free(file);
	}

	return res;
}

static int ifuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi) {
	int i;
	char **dirs;
	AFClient *afc = fuse_get_context()->private_data;

	dirs = afc_get_dir_list(afc, path);

	if(!dirs)
		return -ENOENT;

	for (i = 0; strcmp(dirs[i], ""); i++) {
		filler(buf, dirs[i], NULL, 0);
	}
	
	free_dictionary(dirs);

	return 0;
}

static int ifuse_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
	// exactly the same as open but using a different mode
	AFCFile *file;
	AFClient *afc = fuse_get_context()->private_data;
	
	file = afc_open_file(afc, path, AFC_FILE_WRITE);
	fh_index++;
	fi->fh = fh_index;
	g_hash_table_insert(file_handles, &fh_index, file);
	return 0;
}

static int ifuse_open(const char *path, struct fuse_file_info *fi) {
	AFCFile *file;
	AFClient *afc = fuse_get_context()->private_data;
	uint32 mode = 0;
	
	if ((fi->flags & 3) == O_RDWR || (fi->flags & 3) == O_WRONLY) {
		mode = AFC_FILE_READ;
	} else if ((fi->flags & 3) == O_RDONLY) {
		mode = AFC_FILE_READ;
	} else {
		mode = AFC_FILE_READ;
	}
	
	file = afc_open_file(afc, path, mode);
	
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

	if (size == 0)
		return 0;

	file = g_hash_table_lookup(file_handles, &(fi->fh));
	if (!file){
		return -ENOENT;
	}

	bytes = afc_seek_file(afc, file, offset);
	bytes = afc_read_file(afc, file, buf, size);
	return bytes;
}

static int ifuse_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	int bytes = 0;
	AFCFile *file = NULL;
	AFClient *afc = fuse_get_context()->private_data;
	
	if (size == 0) return 0;
	
	file = g_hash_table_lookup(file_handles, &(fi->fh));
	if (!file) return -ENOENT;
	
	bytes = afc_seek_file(afc, file, offset);
	bytes = afc_write_file(afc, file, buf, size);
	return bytes;
}

static int ifuse_fsync(const char *path, int datasync, struct fuse_file_info *fi) {
	return 0;
}

static int ifuse_release(const char *path, struct fuse_file_info *fi){
	AFCFile *file;
	AFClient *afc = fuse_get_context()->private_data;
	
	file = g_hash_table_lookup(file_handles, &(fi->fh));
	if (!file){
		return -ENOENT;
	}
	afc_close_file(afc, file);
	
	free(file);
	g_hash_table_remove(file_handles, &(fi->fh));

	return 0;
}

void *ifuse_init(struct fuse_conn_info *conn) {
	int port = 0;
	AFClient *afc = NULL;
	
	conn->async_read = 0;

	file_handles = g_hash_table_new(g_int_hash, g_int_equal);

	phone = get_iPhone();
	if (!phone){
		fprintf(stderr, "No iPhone found, is it connected?\n");
		   	return NULL;
	   	}
	
	lockdownd_client *control = new_lockdownd_client(phone);
	if (!lockdownd_hello(control)) {
		fprintf(stderr, "Something went wrong in the lockdownd client.\n");
		return NULL;
	}

	if (!lockdownd_init(phone, &control)) {
		free_iPhone(phone);
		fprintf(stderr, "Something went wrong in the lockdownd client.\n");
		return NULL;
	}
	
	port = lockdownd_start_service(control, "com.apple.afc");
	if (!port) {
		lockdownd_close(control);
		free_iPhone(phone);
		fprintf(stderr, "Something went wrong when starting AFC.");
                return NULL;
	}

	afc = afc_connect(phone, 3432, port);

        return afc;
}

void ifuse_cleanup(void *data) {
	AFClient *afc = (AFClient *)data;

	afc_disconnect(afc);
	lockdownd_close(control);
	free_iPhone(phone);
}

int ifuse_flush(const char *path, struct fuse_file_info *fi) {
	return 0;
}

int ifuse_statfs(const char *path, struct statvfs *stats) {
	AFClient *afc = fuse_get_context()->private_data;
	char **info_raw = afc_get_devinfo(afc);
	uint32 totalspace = 0, freespace = 0, blocksize = 0, i = 0;
	
	if (!info_raw) return -ENOENT;
	
	for (i = 0; strcmp(info_raw[i], ""); i++) {
		if (!strcmp(info_raw[i], "FSTotalBytes")) {
			totalspace = atoi(info_raw[i+1]);
		} else if (!strcmp(info_raw[i], "FSFreeBytes")) {
			freespace = atoi(info_raw[i+1]);
		} else if (!strcmp(info_raw[i], "FSBlockSize")) {
			blocksize = atoi(info_raw[i+1]);
		}
	}
	
	// Now to fill the struct.
	stats->f_bsize = stats->f_frsize = blocksize;
	stats->f_blocks = totalspace / blocksize; // gets the blocks by dividing bytes by blocksize
	stats->f_bfree = stats->f_bavail = freespace / blocksize; // all bytes are free to everyone, I guess.
	stats->f_namemax = 255; // blah
	stats->f_files = stats->f_ffree = 1000000000; // make up any old thing, I guess
	return 0;
}

int ifuse_truncate(const char *path, off_t size) {
	int result = 0;
	AFClient *afc = fuse_get_context()->private_data;
	AFCFile *tfile = afc_open_file(afc, path, AFC_FILE_READ);
	if (!tfile) return -1;
	
	result = afc_truncate_file(afc, tfile, size);
	afc_close_file(afc, tfile);
	return result;
}

int ifuse_ftruncate(const char *path, off_t size, struct fuse_file_info *fi) {
	AFClient *afc = fuse_get_context()->private_data;
	AFCFile *file = g_hash_table_lookup(file_handles, &fi->fh);
	if (!file) return -ENOENT;
	
	return afc_truncate_file(afc, file, size);
}

int ifuse_unlink(const char *path) {
	AFClient *afc = fuse_get_context()->private_data;
	if (afc_delete_file(afc, path)) return 0;
	else return -1;
}

int ifuse_rename(const char *from, const char *to) {
	AFClient *afc = fuse_get_context()->private_data;
	if (afc_rename_file(afc, from, to)) return 0;
	else return -1;
}

int ifuse_mkdir(const char *dir, mode_t ignored) {
	AFClient *afc = fuse_get_context()->private_data;
	if (afc_mkdir(afc, dir)) return 0;
	else return -1;
}

static struct fuse_operations ifuse_oper = {
	.getattr	= ifuse_getattr,
	.statfs		= ifuse_statfs,
	.readdir	= ifuse_readdir,
	.mkdir		= ifuse_mkdir,
	.rmdir		= ifuse_unlink, // AFC uses the same op for both.
	.create		= ifuse_create,
	.open		= ifuse_open,
	.read		= ifuse_read,
	.write		= ifuse_write,
	.truncate 	= ifuse_truncate,
	.ftruncate	= ifuse_ftruncate,
	.unlink		= ifuse_unlink,
	.rename		= ifuse_rename,
	.fsync 		= ifuse_fsync,
	.release	= ifuse_release,
	.init		= ifuse_init,
	.destroy	= ifuse_cleanup
};

int main(int argc, char *argv[]) {
	return fuse_main(argc, argv, &ifuse_oper, NULL);
}
