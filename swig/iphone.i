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
	iPhone* dev;
	iphone_lckd_client_t client;
 } Lockdownd;

 typedef struct {
	Lockdownd* lckd;
	iphone_msync_client_t client;
 } MobileSync;

//now declare funtions to handle creation and deletion of objects
void my_delete_iPhone(iPhone* dev);
Lockdownd* my_new_Lockdownd(iPhone* phone);
void my_delete_Lockdownd(Lockdownd* lckd);
MobileSync* my_new_MobileSync(Lockdownd* lckd);

 %}
/* Parse the header file to generate wrappers */
%include "stdint.i"
%include "plist/swig/plist.i"

typedef struct {
	iphone_device_t dev;
} iPhone;

typedef struct {
	iPhone* dev;
	iphone_lckd_client_t client;
} Lockdownd;

typedef struct {
	Lockdownd* lckd;
	iphone_msync_client_t client;
} MobileSync;

%inline %{
//now define funtions to handle creation and deletion of objects


void my_delete_iPhone(iPhone* dev) {
	if (dev) {
		iphone_free_device ( dev->dev );
		free(dev);
	}
}

Lockdownd* my_new_Lockdownd(iPhone* phone) {
	if (!phone) return NULL;
	Lockdownd* client = (Lockdownd*) malloc(sizeof(Lockdownd));
	client->dev = phone;
	client->client = NULL;
	if (IPHONE_E_SUCCESS == iphone_lckd_new_client ( phone->dev , &(client->client))) {
		return client;
	}
	else {
		free(client);
		return NULL;
	}
}

void my_delete_Lockdownd(Lockdownd* lckd) {
	if (lckd) {
		my_delete_iPhone(lckd->dev);
		iphone_lckd_free_client ( lckd->client );
		free(lckd);
	}
}

MobileSync* my_new_MobileSync(Lockdownd* lckd) {
	if (!lckd || !lckd->dev) return NULL;
	MobileSync* client = NULL;
	int port = 0;
	if (IPHONE_E_SUCCESS == iphone_lckd_start_service ( lckd->client, "com.apple.mobilesync", &port )) {
		client = (MobileSync*) malloc(sizeof(MobileSync));
		client->lckd = lckd;
		client->client = NULL;
		iphone_msync_new_client ( lckd->dev->dev, 3432, port, &(client->client));
	}
	return client;
}

%}


%extend iPhone {             // Attach these functions to struct iPhone
	iPhone() {
		iPhone* phone = (iPhone*) malloc(sizeof(iPhone));
		phone->dev = NULL;
		iphone_set_debug_mask(DBGMASK_LOCKDOWND | DBGMASK_MOBILESYNC);
		return phone;
	}

	~iPhone() {
		my_delete_iPhone($self);
	}

	int InitDevice() {
		if (IPHONE_E_SUCCESS == iphone_get_device ( &($self->dev)))
			return 1;
		return 0;
	}

	Lockdownd* GetLockdownClient() {
		return my_new_Lockdownd($self);
	}
};


%extend Lockdownd {             // Attach these functions to struct Lockdownd
	Lockdownd(iPhone* phone) {
		return my_new_Lockdownd(phone);
	}

	~Lockdownd() {
		my_delete_Lockdownd($self);
	}

	MobileSync* GetMobileSyncClient() {
		return my_new_MobileSync($self);
	}
};

%extend MobileSync {             // Attach these functions to struct MobileSync
	MobileSync(Lockdownd* lckd) {
		return my_new_MobileSync(lckd);
	}

	~MobileSync() {
		my_delete_Lockdownd($self->lckd);
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

