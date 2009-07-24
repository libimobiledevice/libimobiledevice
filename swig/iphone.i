 /* swig.i */
 %module(package="libiphone") iPhone
 %feature("autodoc", "1");
 %{
 /* Includes the header in the wrapper code */
 #include <libiphone/libiphone.h>
 #include <libiphone/lockdown.h>
 #include <libiphone/mobilesync.h>
 #include <plist/plist.h>
 #include "../src/utils.h"
 typedef struct {
	iphone_device_t dev;
 } iPhone;

 typedef struct {
	iPhone* dev;
	lockdownd_client_t client;
 } Lockdownd;

 typedef struct {
	iPhone* dev;
	mobilesync_client_t client;
 } MobileSync;

//now declare funtions to handle creation and deletion of objects
void my_delete_iPhone(iPhone* dev);
Lockdownd* my_new_Lockdownd(iPhone* phone);
void my_delete_Lockdownd(Lockdownd* lckd);
MobileSync* my_new_MobileSync(Lockdownd* lckd);

 %}
/* Parse the header file to generate wrappers */
%include "stdint.i"
%include "cstring.i"
%include "plist/swig/plist.i"

#define DBGMASK_ALL        0xFFFF
#define DBGMASK_NONE       0x0000
#define DBGMASK_LOCKDOWND  (1 << 1)
#define DBGMASK_MOBILESYNC (1 << 2)

typedef struct {
	iphone_device_t dev;
} iPhone;

typedef struct {
	iPhone* dev;
	lockdownd_client_t client;
} Lockdownd;

typedef struct {
	iPhone* dev;
	mobilesync_client_t client;
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
	if (IPHONE_E_SUCCESS == lockdownd_new_client ( phone->dev , &(client->client))) {
		return client;
	}
	else {
		free(client);
		return NULL;
	}
}

void my_delete_Lockdownd(Lockdownd* lckd) {
	if (lckd) {
		lockdownd_free_client ( lckd->client );
		free(lckd);
	}
}

MobileSync* my_new_MobileSync(Lockdownd* lckd) {
	if (!lckd || !lckd->dev) return NULL;
	MobileSync* client = NULL;
	int port = 0;
	if (IPHONE_E_SUCCESS == lockdownd_start_service ( lckd->client, "com.apple.mobilesync", &port )) {
		client = (MobileSync*) malloc(sizeof(MobileSync));
		client->dev = lckd->dev;
		client->client = NULL;
		mobilesync_new_client ( lckd->dev->dev, port, &(client->client));
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

	void set_debug_level(int level) {
		iphone_set_debug_level(level);
	}

	int init_device_by_uuid(char* uuid) {
		if (IPHONE_E_SUCCESS == iphone_get_device_by_uuid ( &($self->dev), uuid))
			return 1;
		return 0;
	}

	int init_device() {
		if (IPHONE_E_SUCCESS == iphone_get_device ( &($self->dev)))
			return 1;
		return 0;
	}

	%newobject get_uuid;
	char* get_uuid(){
		char* uuid = NULL;
		uuid = (char *)iphone_device_get_uuid($self->dev);
		return uuid;
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
		lockdownd_send($self->client, node->node);
	}

	PListNode* receive() {
		PListNode* node = (PListNode*)malloc(sizeof(PListNode));
		node->node = NULL;
		lockdownd_recv($self->client, &(node->node));
		return node;
	}

	MobileSync* get_mobilesync_client() {
		return my_new_MobileSync($self);
	}
};

%extend MobileSync {             // Attach these functions to struct MobileSync
	MobileSync(Lockdownd* lckd) {
		return my_new_MobileSync(lckd);
	}

	~MobileSync() {
		mobilesync_free_client ( $self->client );
		free($self);
	}

	void send(PListNode* node) {
		mobilesync_send($self->client, node->node);
	}

	PListNode* receive() {
		PListNode* node = (PListNode*)malloc(sizeof(PListNode));
		node->node = NULL;
		mobilesync_recv($self->client, &(node->node));
		return node;
	}
};

