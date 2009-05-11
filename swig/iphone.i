 /* swig.i */
 %module(package="libiphone") iPhone
 %feature("autodoc", "1");
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

#define DBGMASK_ALL        0xFFFF
#define DBGMASK_NONE       0x0000
#define DBGMASK_USBMUX     (1 << 1)
#define DBGMASK_LOCKDOWND  (1 << 2)
#define DBGMASK_MOBILESYNC (1 << 3)

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
		return phone;
	}

	~iPhone() {
		my_delete_iPhone($self);
	}

	void set_debug_mask(uint16_t mask) {
		iphone_set_debug_mask(mask);
	}

	int init_device() {
		if (IPHONE_E_SUCCESS == iphone_get_device ( &($self->dev)))
			return 1;
		return 0;
	}

	int init_specific_device(int busnumber, int devicenumber) {
		if (IPHONE_E_SUCCESS == iphone_get_specific_device ( busnumber, devicenumber, &($self->dev)))
			return 1;
		return 0;
	}

	Lockdownd* get_lockdown_client() {
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

	void send(PListNode* node) {
		iphone_lckd_send($self->client, node->node);
	}

	PListNode* receive() {
		PListNode* node = (PListNode*)malloc(sizeof(PListNode));
		node->node = NULL;
		iphone_lckd_recv($self->client, &(node->node));
		return node;
	}

	MobileSync* get_mobile_sync_client() {
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

	void send(PListNode* node) {
		iphone_msync_send($self->client, node->node);
	}

	PListNode* receive() {
		PListNode* node = (PListNode*)malloc(sizeof(PListNode));
		node->node = NULL;
		iphone_msync_recv($self->client, &(node->node));
		return node;
	}
};

