/*
 * idevicecopycontainer.c
 * Copy an application's root container (via house arrest/AFC).
 *
 * Copyright (c) 2018 Shane Garrett All Rights Reserved.
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

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/house_arrest.h>
#include <libimobiledevice/afc.h>
#include "common/debug.h"

/* struct for the tool's arguments */
typedef struct {
    bool debug;
    bool help;
    const char *udid;
    const char *bundle_id;
    const char *directory;
} args_t;

static void print_usage(int argc, char **argv)
{
    char *name = NULL;
    name = strrchr(argv[0], '/');
    printf("Usage: %s [OPTIONS] BUNDLE_ID DIRECTORY\n", 
        (name ? name + 1: argv[0]));
    printf("Copy an application's root container (via house arrest/AFC).\n");
    printf("\n");
    printf("options:\n");
    printf("  -d, --debug\t\tenable communication debugging\n");
    printf("  -u, --udid UDID\ttarget specific device by its 40-digit device UDID\n");
    printf("  -h, --help\t\tprints usage information\n");
}

/* fill out args struct from the command line */
static bool parse_args(int argc, char **argv, args_t *args)
{
    bool ok = false;
    int i;
    int pos_i = 0;
    assert(args);
    memset(args, 0, sizeof(args_t));
    /* parse command line arguments */
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            args->help = true;
            break;
        } else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
            args->debug = true;
            continue;
        } else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--udid")) {
            args->udid = argv[++i];
            continue;
        } else {
            /* handle positional args */
            if (pos_i == 0) {
                pos_i++;
                args->bundle_id = argv[i];
            } else if (pos_i == 1) {
                pos_i++;
                args->directory = argv[i];
            }
            continue;
        }
    }
    /* both positional args need to be specified */
    ok = (pos_i == 2);
    return ok;
}

static const char *mode_string(mode_t mode)
{
    const char *name = NULL;
    switch(mode) {
    case S_IFREG:
        name = "S_IFREG";
        break;
    case S_IFDIR:
        name = "S_IFDIR";
        break;
    case S_IFLNK:
        name = "S_IFLNK";
        break;
    case S_IFCHR:
        name = "S_IFCHR";
        break;
    case S_IFIFO:
        name = "S_IFIFO";
        break;
    case S_IFSOCK:
        name = "S_IFSOCK";
        break;
    default:
        name = "UNKNOWN";
        break;
    }
    return name;
}

/* 
 * Get some basic information about the file and store in a stat struct.
 * This is mostly cribbed from ifuse.
 *
 * CAVEAT: Not all fields in stat are populated. 
 */
static afc_error_t _afc_stat(afc_client_t afc, const char *path, 
    struct stat *stbuf)
{
    int i;
    afc_error_t ret = AFC_E_UNKNOWN_ERROR;
    char **info = NULL;

    ret = afc_get_file_info(afc, path, &info);

    memset(stbuf, 0, sizeof(struct stat));
    if (ret == AFC_E_SUCCESS && info != NULL) {
        // get file attributes from info list
        for (i = 0; info[i]; i += 2) {
            if (!strcmp(info[i], "st_size")) {
                stbuf->st_size = atoll(info[i+1]);
            } else if (!strcmp(info[i], "st_blocks")) {
                stbuf->st_blocks = atoi(info[i+1]);
            } else if (!strcmp(info[i], "st_ifmt")) {
                if (!strcmp(info[i+1], "S_IFREG")) {
                    stbuf->st_mode = S_IFREG;
                } else if (!strcmp(info[i+1], "S_IFDIR")) {
                    stbuf->st_mode = S_IFDIR;
                } else if (!strcmp(info[i+1], "S_IFLNK")) {
                    stbuf->st_mode = S_IFLNK;
                } else if (!strcmp(info[i+1], "S_IFBLK")) {
                    stbuf->st_mode = S_IFBLK;
                } else if (!strcmp(info[i+1], "S_IFCHR")) {
                    stbuf->st_mode = S_IFCHR;
                } else if (!strcmp(info[i+1], "S_IFIFO")) {
                    stbuf->st_mode = S_IFIFO;
                } else if (!strcmp(info[i+1], "S_IFSOCK")) {
                    stbuf->st_mode = S_IFSOCK;
                }
            } else if (!strcmp(info[i], "st_nlink")) {
                stbuf->st_nlink = atoi(info[i+1]);
            } else if (!strcmp(info[i], "st_mtime")) {
                stbuf->st_mtime = (time_t)(atoll(info[i+1]) / 1000000000);
            }
#ifdef _DARWIN_FEATURE_64_BIT_INODE
            else if (!strcmp(info[i], "st_birthtime")) { /* available on iOS 7+ */
                stbuf->st_birthtime = (time_t)(atoll(info[i+1]) / 1000000000);
            }
#endif
        }

        // set permission bits according to the file type
        //if (S_ISDIR(stbuf->st_mode)) {
        //    stbuf->st_mode |= 0755;
        //} else if (S_ISLNK(stbuf->st_mode)) {
        //    stbuf->st_mode |= 0777;
        //} else {
        //    stbuf->st_mode |= 0644;
        //}

        // and set some additional info
        //stbuf->st_uid = getuid();
        //stbuf->st_gid = getgid();
        //stbuf->st_blksize = g_blocksize;
    }
    if (info) {
        afc_dictionary_free(info);
        info = NULL;
    }
    return ret;
}

static bool _copy_file(afc_client_t afc, const char *dst_path, 
    const char *src_path, const struct stat *stbuf)
{
    assert(afc);
    assert(dst_path);
    assert(src_path);
    assert(stbuf);
    bool ok = false;
    uint64_t afd = 0;
    int fd = -1;
    afc_error_t afcrc = AFC_E_UNKNOWN_ERROR;
    const size_t BUF_SIZE = 4096;
    char buf[BUF_SIZE];

    /* open the file on device */
    afcrc = afc_file_open(afc, src_path, AFC_FOPEN_RDONLY, &afd);
    if (afcrc != AFC_E_SUCCESS) {
        printf("Error opening file '%s':  %d\n", src_path, afcrc);
        goto cleanup;
    }
    /* open the local file */
    fd = open(dst_path, O_CREAT | O_WRONLY, 0644);
    if (fd == -1) {
        printf("Error creating file '%s': %s(%d)\n", dst_path,
            strerror(errno), errno);
        goto cleanup;
    }
    /* Read chunks from the remote file, writing them to the local file */
    off_t total_remaining = stbuf->st_size;
    ssize_t wrc = 0;
    assert(afcrc == AFC_E_SUCCESS);
    while(total_remaining > 0 && afcrc == AFC_E_SUCCESS && wrc != -1) {
        /* read a chunk */
        uint32_t cnt_read = 0;
        afcrc = afc_file_read(afc, afd, buf, BUF_SIZE, &cnt_read);
        if (afcrc == AFC_E_SUCCESS) {
            total_remaining -= cnt_read;
            off_t cnt_to_write = cnt_read;
            off_t cnt_written = 0;
            /* write that chunk (possibly multiple writes...) */
            while(cnt_written < cnt_to_write && wrc != -1) {
                wrc = write(fd, buf+cnt_written, cnt_to_write-cnt_written);
                if (wrc == -1) {
                    printf("Error writing '%s': %s(%d)\n", dst_path, 
                        strerror(errno), errno);
                    goto cleanup;
                } else {
                    cnt_written += wrc;
                }
            }
        } else {
            printf("Error reading '%s': %d\n", src_path, afcrc);
            goto cleanup;
        }
    }
    /* Finished */
    ok = true;
cleanup:
    if (afd) {
        afc_file_close(afc, afd);
        afd = 0;
    }
    if (fd == -1) {
        close(fd);
        fd = -1;
    }
    return ok;
}

static void copy_it(afc_client_t afc, const char *dst_path, 
    const char *src_path)
{
    assert(afc);
    assert(dst_path);
    assert(src_path);
    afc_error_t afcrc = AFC_E_UNKNOWN_ERROR;
    struct stat stbuf;
    char **dirlist = NULL;

    afcrc = _afc_stat(afc, src_path, &stbuf);
    if (afcrc != AFC_E_SUCCESS) {
        if (afcrc == AFC_E_PERM_DENIED) {
            printf("Skipping '%s' due to permission denied when getting "
                "info.\n", src_path);
        } else {
            printf("Skipping '%s' due to error getting info.  Error:%d\n",
                src_path, afcrc);
        }
        goto cleanup;
    }
    if (stbuf.st_mode == S_IFDIR) {
        /* A directory, read and process the entries */
        afcrc = afc_read_directory(afc, src_path, &dirlist);
        if (afcrc != AFC_E_SUCCESS) {
            if (afcrc == AFC_E_PERM_DENIED) {
                printf("Skipping '%s' due to permission denied when getting "
                    "directory listing.\n", src_path);
            } else {
                printf("Skipping '%s' due to error getting directory listing. "
                    "Error: %d\n", src_path, afcrc);
            }
            goto cleanup;
        }
        /* Create the local directory */
        if (mkdir(dst_path, 0755) && errno != EEXIST) {
            printf("Error creating directory '%s': %s(%d)\n", dst_path, 
                strerror(errno), errno);
            goto cleanup;
        }
        char *tmp_src = NULL;
        char *tmp_dst = NULL;
        /* Iternate over the paths, recursively calling "copy_it" for each */
        for (int i = 0; dirlist[i]; i++) {
            const char *dl = dirlist[i];
            assert(dl);
            if (!strcmp(dl, ".") || !strcmp(dl, "..")) {
                /* Skip '.' and '..' entries */
                continue;
            }
            /* concatenate the current src and dst to the entry */
            int dl_len = strlen(dl);
            int tmp_src_len = strlen(src_path) + dl_len + 2;
            assert(!tmp_src);
            tmp_src = malloc(tmp_src_len);
            snprintf(tmp_src, tmp_src_len, "%s/%s", src_path, dl);
            int tmp_dst_len = strlen(dst_path) + dl_len + 2;
            assert(!tmp_dst);
            tmp_dst = malloc(tmp_dst_len);
            snprintf(tmp_dst, tmp_dst_len, "%s/%s", dst_path, dl);
            copy_it(afc, tmp_dst, tmp_src);
            if (tmp_src) {
                free(tmp_src);
                tmp_src = NULL;
            }
            if (tmp_dst) {
                free(tmp_dst);
                tmp_dst = NULL;
            }
        }
    } else if (stbuf.st_mode == S_IFREG) {
        /* A regular file, copy it */
        _copy_file(afc, dst_path, src_path, &stbuf);
    } else {
        /* (currently) unsupported file type */
        printf("Skipping '%s' due to unsupported file mode %s(%d).\n", src_path,
            mode_string(stbuf.st_mode), stbuf.st_mode);
    }
cleanup:
    if (dirlist) {
        afc_dictionary_free(dirlist);
        dirlist = NULL;
    }
}

int main(int argc, char **argv)
{
    int rc = 0;
    args_t args;
    idevice_t device = NULL;
    idevice_error_t irc = IDEVICE_E_UNKNOWN_ERROR;
    lockdownd_error_t ldrc = LOCKDOWN_E_UNKNOWN_ERROR;
    house_arrest_error_t harc = HOUSE_ARREST_E_UNKNOWN_ERROR;
    afc_error_t afcrc = AFC_E_UNKNOWN_ERROR;
    lockdownd_client_t ld_client = NULL;
    lockdownd_service_descriptor_t ld_service = NULL;
    house_arrest_client_t ha_client = NULL;
    afc_client_t afc_client = NULL;

    /* parse command line arguments */
    if (!parse_args(argc, argv, &args)) {
        rc = -1;
        print_usage(argc, argv);
        goto cleanup;
    }

    if (args.help) {
        /* show help and exit */
        print_usage(argc, argv);
        rc = 0;
        goto cleanup;
    }
    if (args.debug) {
        /* enable debug logging */
        idevice_set_debug_level(1);
        internal_set_debug_level(1);
    }
    /* connect to the device */
    irc = idevice_new(&device, args.udid);
    if (irc != IDEVICE_E_SUCCESS) {
        if (args.udid) {
            printf("No device found with udid %s, is it plugged in?\n", 
                args.udid);
        } else {
            printf("No device found, is it plugged in?\n");
        }
        goto cleanup;
    }
    ldrc = lockdownd_client_new_with_handshake(device, &ld_client, 
        "idevicecopycontainer");
    if (ldrc != LOCKDOWN_E_SUCCESS) {
        if (ldrc == LOCKDOWN_E_PASSWORD_PROTECTED) {
            printf("Please disable the password protection on your device and try again.\n");
            printf("The device does not allow pairing as long as a password has been set.\n");
            printf("You can enable it again after the connection succeeded.\n");

        } else if (ldrc == LOCKDOWN_E_PAIRING_DIALOG_RESPONSE_PENDING) {
            printf("Please dismiss the trust dialog on your device and try again.\n");
            printf("The device does not allow pairing as long as the dialog has not been accepted.\n");
        } else {
            printf("Failed to connect to lockdownd service on the device.\n");
            printf("Try again. If it still fails try rebooting your device.\n");
        }
        rc = -1;
        goto cleanup;
    }
    ldrc = lockdownd_start_service(ld_client, HOUSE_ARREST_SERVICE_NAME, 
        &ld_service);
    if (ldrc != LOCKDOWN_E_SUCCESS) {
        printf("Failed to start service '%s' on the device.\n", 
            HOUSE_ARREST_SERVICE_NAME);
        rc = -1;
        goto cleanup;
    }
    harc = house_arrest_client_new(device, ld_service, &ha_client);
    if (harc != HOUSE_ARREST_E_SUCCESS) {
        printf("Failed to create house arrest client.  Error: %d\n", harc);
        rc = -1;
        goto cleanup;
    }
    harc = house_arrest_send_command(ha_client, "VendContainer", 
        args.bundle_id);
    if (harc != HOUSE_ARREST_E_SUCCESS) {
        printf("Unable to send VendContainer command for %s.  Error: %d\n", 
            args.bundle_id, harc);
        rc = -1;
        goto cleanup;
    }
    /* Check whether VendContainer succeeded */
    plist_t dict = NULL;
    harc = house_arrest_get_result(ha_client, &dict);
    if ( harc != HOUSE_ARREST_E_SUCCESS) {
        printf("Could not get result from house arrest.  Error: %d\n", harc);
        rc = -1;
        goto cleanup;
    }
    plist_t node = plist_dict_get_item(dict, "Error");
    if (node) {
        char *str = NULL;
        plist_get_string_val(node, &str);
        printf("ERROR: %s\n", str);
        if (str && !strcmp(str, "InstallationLookupFailed")) {
            printf("The App '%s' is either not present on the device, or "
                "there was an error.\n", args.bundle_id);
        }
        if (str) {
            free(str);
            str = NULL;
        }
        goto cleanup;
    }
    afcrc = afc_client_new_from_house_arrest_client(ha_client, &afc_client);
    if (afcrc != AFC_E_SUCCESS) {
        printf("Failed to create AFC client.  Error: %d\n", afcrc);
        rc = -1;
        goto cleanup;
    }
    /* Copy the files, "." will start at the data container's root */
    copy_it(afc_client, args.directory, ".");
cleanup:
    if (afc_client) {
        afc_client_free(afc_client);
        afc_client = NULL;
    }
    if (ha_client) {
        house_arrest_client_free(ha_client);
        ha_client = NULL;
    }
    if (ld_client) {
        lockdownd_client_free(ld_client);
        ld_client = NULL;
    }
    if (device) {
        idevice_free(device);
        device = NULL;
    }

    return rc;
}