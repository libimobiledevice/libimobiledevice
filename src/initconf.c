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
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <glib.h>

#include "libiphone/libiphone.h"
#include "userpref.h"
#include "lockdown.h"
#include "utils.h"

/** Generates a 2048 byte key, split into a function so that it can be run in a
 *  thread.
 *
 * @param key The pointer to the desired location of the new key.
 */
void generate_key(gpointer key)
{
	gnutls_x509_privkey_generate(*((gnutls_x509_privkey_t *) key), GNUTLS_PK_RSA, 2048, 0);
	g_thread_exit(0);
}

/** Simple function that generates a spinner until the mutex is released.
 */
void progress_bar(gpointer mutex)
{
	const char *spinner = "|/-\\|/-\\";
	int i = 0;

	while (!g_static_mutex_trylock((GStaticMutex *) mutex)) {
		usleep(500000);
		printf("Generating key... %c\r", spinner[i++]);
		fflush(stdout);
		if (i > 8)
			i = 0;
	}
	printf("Generating key... done\n");
	g_thread_exit(0);
}

int main(int argc, char *argv[])
{
	GThread *progress_thread, *key_thread;
	GError *err;
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;
	char *host_id = NULL;
	gnutls_x509_privkey_t root_privkey;
	gnutls_x509_privkey_t host_privkey;
	gnutls_x509_crt_t root_cert;
	gnutls_x509_crt_t host_cert;

	iphone_set_debug(1);

	// Create the thread
	if (!g_thread_supported()) {
		g_thread_init(NULL);
	}
	gnutls_global_init();

	printf("This program generates keys required to connect with the iPhone\n");
	printf("It only needs to be run ONCE.\n\n");
	printf("Additionally it may take several minutes to run, please be patient.\n\n");


	gnutls_x509_privkey_init(&root_privkey);
	gnutls_x509_privkey_init(&host_privkey);

	gnutls_x509_crt_init(&root_cert);
	gnutls_x509_crt_init(&host_cert);

	/* generate HostID */
	host_id = lockdownd_generate_hostid();

	/* generate root key */
	g_static_mutex_lock(&mutex);
	if ((key_thread = g_thread_create((GThreadFunc) generate_key, &root_privkey, TRUE, &err)) == NULL) {
		printf("Thread create failed: %s!!\n", err->message);
		g_error_free(err);
	}
	if ((progress_thread = g_thread_create((GThreadFunc) progress_bar, &mutex, TRUE, &err)) == NULL) {
		printf("Thread create failed: %s!!\n", err->message);
		g_error_free(err);
	}
	g_thread_join(key_thread);
	g_static_mutex_unlock(&mutex);
	g_thread_join(progress_thread);

	/* generate host key */
	g_static_mutex_init(&mutex);
	g_static_mutex_lock(&mutex);
	if ((key_thread = g_thread_create((GThreadFunc) generate_key, &host_privkey, TRUE, &err)) == NULL) {
		printf("Thread create failed: %s!!\n", err->message);
		g_error_free(err);
	}
	if ((progress_thread = g_thread_create((GThreadFunc) progress_bar, &mutex, TRUE, &err)) == NULL) {
		printf("Thread create failed: %s!!\n", err->message);
		g_error_free(err);
	}
	g_thread_join(key_thread);
	g_static_mutex_unlock(&mutex);
	g_thread_join(progress_thread);

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
	gnutls_datum_t root_key_pem = { NULL, 0 };
	gnutls_datum_t host_key_pem = { NULL, 0 };

	gnutls_x509_privkey_export(root_privkey, GNUTLS_X509_FMT_PEM, NULL, &root_key_pem.size);
	gnutls_x509_privkey_export(host_privkey, GNUTLS_X509_FMT_PEM, NULL, &host_key_pem.size);

	root_key_pem.data = gnutls_malloc(root_key_pem.size);
	host_key_pem.data = gnutls_malloc(host_key_pem.size);

	gnutls_x509_privkey_export(root_privkey, GNUTLS_X509_FMT_PEM, root_key_pem.data, &root_key_pem.size);
	gnutls_x509_privkey_export(host_privkey, GNUTLS_X509_FMT_PEM, host_key_pem.data, &host_key_pem.size);

	gnutls_datum_t root_cert_pem = { NULL, 0 };
	gnutls_datum_t host_cert_pem = { NULL, 0 };

	gnutls_x509_crt_export(root_cert, GNUTLS_X509_FMT_PEM, NULL, &root_cert_pem.size);
	gnutls_x509_crt_export(host_cert, GNUTLS_X509_FMT_PEM, NULL, &host_cert_pem.size);

	root_cert_pem.data = gnutls_malloc(root_cert_pem.size);
	host_cert_pem.data = gnutls_malloc(host_cert_pem.size);

	printf("Generating root certificate...");
	gnutls_x509_crt_export(root_cert, GNUTLS_X509_FMT_PEM, root_cert_pem.data, &root_cert_pem.size);
	printf("done\n");

	printf("Generating host certificate...");
	gnutls_x509_crt_export(host_cert, GNUTLS_X509_FMT_PEM, host_cert_pem.data, &host_cert_pem.size);
	printf("done\n");


	/* store values in config file */
	init_config_file(host_id, &root_key_pem, &host_key_pem, &root_cert_pem, &host_cert_pem);

	gnutls_free(root_key_pem.data);
	gnutls_free(host_key_pem.data);
	gnutls_free(root_cert_pem.data);
	gnutls_free(host_cert_pem.data);

	return 0;
}
