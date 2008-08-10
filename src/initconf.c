/*
 * userpref.c
 * contains methods to access user specific certificates IDs and more.
 *
 * Copyright (c) 2008 Jonathan Beck All Rights Reserved.
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
#include <stdlib.h>
#include <gnutls/gnutls.h>
#include <glib.h>
#include "userpref.h"

int debug = 1;

int get_rand(int min, int max) {
	int retval = (rand() % (max - min)) + min;
	return retval;
}

char *lockdownd_generate_hostid() {
	char *hostid = (char*)malloc(sizeof(char) * 37); // HostID's are just UUID's, and UUID's are 36 characters long
	const char *chars = "ABCDEF0123456789";
	srand(time(NULL));
	int i = 0;
	
	for (i = 0; i < 36; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			hostid[i] = '-';
			continue;
		} else {
			hostid[i] = chars[get_rand(0,16)];
		}
	}
	hostid[36] = '\0';
	return hostid;
}

int main(int argc, char *argv[]) {

	gnutls_global_init();

	char* host_id = NULL; //"29942970-207913891623273984"
	gnutls_x509_privkey_t root_privkey;
	gnutls_x509_privkey_t host_privkey;

	gnutls_x509_crt_t root_cert;
	gnutls_x509_crt_t host_cert;

	gnutls_x509_privkey_init(&root_privkey);
	gnutls_x509_privkey_init(&host_privkey);

	gnutls_x509_crt_init(&root_cert);
	gnutls_x509_crt_init(&host_cert);

	/* generate HostID */
	//TODO
	host_id = lockdownd_generate_hostid();
	if (debug) printf("HostID: %s\n", host_id);
	/* generate keys */
	gnutls_x509_privkey_generate(root_privkey, GNUTLS_PK_RSA, 2048, 0);
	gnutls_x509_privkey_generate(host_privkey, GNUTLS_PK_RSA, 2048, 0);

	/* generate certificates */
	gnutls_x509_crt_set_key(root_cert, root_privkey);
	gnutls_x509_crt_set_serial(root_cert, "\x00", 1);
	gnutls_x509_crt_set_version(root_cert, 3);
	gnutls_x509_crt_set_ca_status(root_cert, 1);
	gnutls_x509_crt_set_activation_time(root_cert, time(NULL));
	gnutls_x509_crt_set_expiration_time(root_cert, time(NULL) + (60 * 60 * 24 * 365 * 10));
	gnutls_x509_crt_sign(root_cert, root_cert, root_privkey);


	gnutls_x509_crt_set_key(host_cert, host_privkey);
	gnutls_x509_crt_set_serial(host_cert, "\x00", 1);
	gnutls_x509_crt_set_version(host_cert, 3);
	gnutls_x509_crt_set_ca_status(host_cert, 0);
	gnutls_x509_crt_set_key_usage(host_cert, GNUTLS_KEY_KEY_ENCIPHERMENT | GNUTLS_KEY_DIGITAL_SIGNATURE);
	gnutls_x509_crt_set_activation_time(host_cert, time(NULL));
	gnutls_x509_crt_set_expiration_time(host_cert, time(NULL) + (60 * 60 * 24 * 365 * 10));
	gnutls_x509_crt_sign(host_cert, root_cert, root_privkey);


	/* export to PEM format */
	gnutls_datum_t root_key_pem = {NULL, 0};
	gnutls_datum_t host_key_pem = {NULL, 0};

	gnutls_x509_privkey_export (root_privkey, GNUTLS_X509_FMT_PEM,  NULL, &root_key_pem.size);
	gnutls_x509_privkey_export (host_privkey, GNUTLS_X509_FMT_PEM,  NULL, &host_key_pem.size);

	root_key_pem.data = gnutls_malloc(root_key_pem.size);
	host_key_pem.data = gnutls_malloc(host_key_pem.size);

	gnutls_x509_privkey_export (root_privkey, GNUTLS_X509_FMT_PEM,  root_key_pem.data, &root_key_pem.size);
	gnutls_x509_privkey_export (host_privkey, GNUTLS_X509_FMT_PEM,  host_key_pem.data, &host_key_pem.size);

	gnutls_datum_t root_cert_pem = {NULL, 0};
	gnutls_datum_t host_cert_pem = {NULL, 0};

	gnutls_x509_crt_export (root_cert, GNUTLS_X509_FMT_PEM,  NULL, &root_cert_pem.size);
	gnutls_x509_crt_export (host_cert, GNUTLS_X509_FMT_PEM,  NULL, &host_cert_pem.size);

	root_cert_pem.data = gnutls_malloc(root_cert_pem.size);
	host_cert_pem.data = gnutls_malloc(host_cert_pem.size);

	gnutls_x509_crt_export (root_cert, GNUTLS_X509_FMT_PEM,  root_cert_pem.data, &root_cert_pem.size);
	gnutls_x509_crt_export (host_cert, GNUTLS_X509_FMT_PEM,  host_cert_pem.data, &host_cert_pem.size);


	/* store values in config file */
	
	init_config_file(host_id, &root_key_pem, &host_key_pem, &root_cert_pem, &host_cert_pem);

	gnutls_free(root_key_pem.data);
	gnutls_free(host_key_pem.data);
	gnutls_free(root_cert_pem.data);
	gnutls_free(host_cert_pem.data);

	return 0;
}

