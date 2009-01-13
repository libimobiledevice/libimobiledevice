 /* swig.i */
 %module(package="libiphone") iPhone
 %{
 /* Includes the header in the wrapper code */
 #include <libiphone/libiphone.h>
 #include <plist/plist.h>
#include "../src/utils.h"
 typedef struct {
	iphone_device_t dev;
 } iPhone;

 typedef struct {
	iphone_device_t dev;
	iphone_lckd_client_t client;
 } Lockdownd;

 typedef struct {
	iphone_msync_client_t client;
 } MobileSync;
 %}
/* Parse the header file to generate wrappers */
%include "stdint.i"
%include "plist/swig/plist.i"

typedef struct {
	iphone_device_t dev;
} iPhone;

typedef struct {
	iphone_device_t dev;
	iphone_lckd_client_t client;
} Lockdownd;

typedef struct {
	iphone_msync_client_t client;
} MobileSync;

%extend iPhone {             // Attach these functions to struct iPhone
	iPhone() {
		iPhone* phone = (iPhone*) malloc(sizeof(iPhone));
		phone->dev = NULL;
		iphone_set_debug_mask(DBGMASK_LOCKDOWND | DBGMASK_MOBILESYNC);
		return phone;
	}

	~iPhone() {
		iphone_free_device ( $self->dev );
		free($self);
	}

	int InitDevice() {
		if (IPHONE_E_SUCCESS == iphone_get_device ( &($self->dev)))
			return 1;
		return 0;
	}

	Lockdownd* GetLockdownClient() {
		Lockdownd* client = (Lockdownd*) malloc(sizeof(Lockdownd));
		client->client = NULL;
		client->dev = NULL;
		if (IPHONE_E_SUCCESS == iphone_lckd_new_client ( $self->dev , &(client->client)) ) {
			client->dev = $self->dev;
			return client;
		}
		free(client);
		return NULL;
	}
};

%extend Lockdownd {             // Attach these functions to struct Lockdownd
	Lockdownd(iPhone* phone) {
		if (!phone) return NULL;
		Lockdownd* client = (Lockdownd*) malloc(sizeof(Lockdownd));
		client->client = NULL;
		if (IPHONE_E_SUCCESS == iphone_lckd_new_client ( phone->dev , &(client->client))) {
			client->dev = phone->dev;
			return client;
		}
		else {
			free(client);
			return NULL;
		}
	}

	~Lockdownd() {
		iphone_lckd_free_client ( $self->client );
		free($self);
	}

	MobileSync* GetMobileSyncClient() {
		int port = 0;
		if (IPHONE_E_SUCCESS == iphone_lckd_start_service ( $self->client, "com.apple.mobilesync", &port )) {
			MobileSync* client = (MobileSync*) malloc(sizeof(MobileSync));
			client->client = NULL;
			if (IPHONE_E_SUCCESS == iphone_msync_new_client ( $self->dev, 3432, port, &(client->client)))
				return client;
		}
		return NULL;
	}
};

%extend MobileSync {             // Attach these functions to struct MobileSync
	MobileSync(iPhone* phone, int src_port, int dst_port) {
		if (!phone) return NULL;
		MobileSync* client = (MobileSync*) malloc(sizeof(MobileSync));
		client->client = NULL;
		iphone_msync_new_client ( phone->dev, src_port, dst_port, &(client->client));
		return client;
	}

	~MobileSync() {
		iphone_msync_free_client ( $self->client );
		free($self);
	}

	void Send(PListNode* node) {
		iphone_msync_send($self->client, node->node);
	}

	PListNode* Receive() {
		PListNode* node = (PListNode*)malloc(sizeof(PListNode));
		node->node = NULL;
		iphone_msync_recv($self->client, &(node->node));
		return node;
	}
};

