#ifndef AFC_H
#define AFC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libiphone/libiphone.h>

typedef enum {
	AFC_FOPEN_RDONLY   = 0x00000001, // r   O_RDONLY
	AFC_FOPEN_RW       = 0x00000002, // r+  O_RDWR   | O_CREAT
	AFC_FOPEN_WRONLY   = 0x00000003, // w   O_WRONLY | O_CREAT  | O_TRUNC
	AFC_FOPEN_WR       = 0x00000004, // w+  O_RDWR   | O_CREAT  | O_TRUNC
	AFC_FOPEN_APPEND   = 0x00000005, // a   O_WRONLY | O_APPEND | O_CREAT
	AFC_FOPEN_RDAPPEND = 0x00000006  // a+  O_RDWR   | O_APPEND | O_CREAT
} afc_file_mode_t;

typedef enum {
	AFC_HARDLINK = 1,
	AFC_SYMLINK = 2
} afc_link_type_t;

struct afc_client_int;
typedef struct afc_client_int *afc_client_t;

//afc related functions
iphone_error_t afc_new_client ( iphone_device_t device, int dst_port, afc_client_t *client );
iphone_error_t afc_free_client ( afc_client_t client );
int afc_get_afcerror ( afc_client_t client );
int afc_get_errno ( afc_client_t client );

iphone_error_t afc_get_devinfo ( afc_client_t client, char ***infos );
iphone_error_t afc_get_dir_list ( afc_client_t client, const char *dir, char ***list);

iphone_error_t afc_get_file_info ( afc_client_t client, const char *filename, char ***infolist );
iphone_error_t afc_open_file ( afc_client_t client, const char *filename, afc_file_mode_t file_mode, uint64_t *handle );
iphone_error_t afc_close_file ( afc_client_t client, uint64_t handle);
iphone_error_t afc_lock_file ( afc_client_t client, uint64_t handle, int operation);
iphone_error_t afc_read_file ( afc_client_t client, uint64_t handle, char *data, int length, uint32_t *bytes);
iphone_error_t afc_write_file ( afc_client_t client, uint64_t handle, const char *data, int length, uint32_t *bytes);
iphone_error_t afc_seek_file ( afc_client_t client, uint64_t handle, int64_t offset, int whence);
iphone_error_t afc_truncate_file ( afc_client_t client, uint64_t handle, uint64_t newsize);
iphone_error_t afc_delete_file ( afc_client_t client, const char *path);
iphone_error_t afc_rename_file ( afc_client_t client, const char *from, const char *to);
iphone_error_t afc_mkdir ( afc_client_t client, const char *dir);
iphone_error_t afc_truncate ( afc_client_t client, const char *path, off_t newsize);
iphone_error_t afc_make_link ( afc_client_t client, afc_link_type_t linktype, const char *target, const char *linkname);

#ifdef __cplusplus
}
#endif

#endif
