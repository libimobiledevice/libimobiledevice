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


AFClient *afc = NULL;
GHashTable *file_handles;
int fh_index = 0;

int debug = 0;

static int ifuse_getattr(const char *path, struct stat *stbuf) {
	int res = 0;
	AFCFile *file;

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

	dirs = afc_get_dir_list(afc, path);
	for (i = 0; strcmp(dirs[i], ""); i++) {
		filler(buf, dirs[i], NULL, 0);
	}
	
	free_dictionary(dirs);

	return 0;
}

static int ifuse_open(const char *path, struct fuse_file_info *fi) {
	AFCFile *file;

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
		
	//if (!lockdownd_start_SSL_session(control, "29942970-207913891623273984")) {
		fprintf(stderr, "Something went wrong in GnuTLS.\n");
		return NULL;
	}
	
	port = lockdownd_start_service(control, "com.apple.afc");
	if (!port) {
		fprintf(stderr, "Something went wrong when starting AFC.");
                return NULL;
	}

	afc = afc_connect(phone, 3432, port);

        return afc;
}

void ifuse_cleanup() {
	afc_disconnect(afc);
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
