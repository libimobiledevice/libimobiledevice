 /* swig.i */
 %module iphone
 %feature("autodoc", "1");
 %{
 /* Includes the header in the wrapper code */
 #include <libiphone/libiphone.h>
 #include <libiphone/lockdown.h>
 #include <libiphone/mobilesync.h>
 #include <plist/plist.h>
 #include <plist/plist++.h>
 #include "../src/debug.h"
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
PList::Node* new_node_from_plist(plist_t node);

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
		iphone_device_free(dev->dev);
		free(dev);
	}
}

Lockdownd* my_new_Lockdownd(iPhone* phone) {
	if (!phone) return NULL;
	Lockdownd* client = (Lockdownd*) malloc(sizeof(Lockdownd));
	client->dev = phone;
	client->client = NULL;
	if (LOCKDOWN_E_SUCCESS == lockdownd_client_new_with_handshake(phone->dev , &(client->client), NULL)) {
		return client;
	}
	else {
		free(client);
		return NULL;
	}
}

void my_delete_Lockdownd(Lockdownd* lckd) {
	if (lckd) {
		lockdownd_client_free(lckd->client);
		free(lckd);
	}
}

MobileSync* my_new_MobileSync(Lockdownd* lckd) {
	if (!lckd || !lckd->dev) return NULL;
	MobileSync* client = NULL;
	int port = 0;
	if (LOCKDOWN_E_SUCCESS == lockdownd_start_service(lckd->client, "com.apple.mobilesync", &port)) {
		client = (MobileSync*) malloc(sizeof(MobileSync));
		client->dev = lckd->dev;
		client->client = NULL;
		mobilesync_client_new(lckd->dev->dev, port, &(client->client));
	}
	return client;
}

PList::Node* new_node_from_plist(plist_t node)
{
	PList::Node* ret = NULL;
	plist_type subtype = plist_get_node_type(node);
	switch(subtype)
	{
	    case PLIST_DICT:
		ret = new PList::Dictionary(node);
		break;
	    case PLIST_ARRAY:
		ret = new PList::Array(node);
		break;
	    case PLIST_BOOLEAN:
		ret = new PList::Boolean(node);
		break;
	    case PLIST_UINT:
		ret = new PList::Integer(node);
		break;
	    case PLIST_REAL:
		ret = new PList::Real(node);
		break;
	    case PLIST_STRING:
		ret = new PList::String(node);
		break;
	    case PLIST_DATE:
		ret = new PList::Date(node);
		break;
	    case PLIST_DATA:
		ret = new PList::Data(node);
		break;
	    default:
		break;
	}
	return ret;
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
		if (IPHONE_E_SUCCESS == iphone_device_new(&($self->dev), uuid))
			return 1;
		return 0;
	}

	int init_device() {
		if (IPHONE_E_SUCCESS == iphone_device_new(&($self->dev), NULL))
			return 1;
		return 0;
	}

	%newobject get_uuid;
	char* get_uuid(){
		char* uuid = NULL;
		iphone_device_get_uuid($self->dev, &uuid);
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

	void send(PList::Node* node) {
		lockdownd_send($self->client, node->GetPlist());
	}

	PList::Node* receive() {
		plist_t node = NULL;
		lockdownd_recv($self->client, &node);
		return new_node_from_plist(node);
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
		mobilesync_client_free($self->client);
		free($self);
	}

	void send(PList::Node* node) {
		mobilesync_send($self->client, node->GetPlist());
	}

	PList::Node* receive() {
		plist_t node = NULL;
		mobilesync_recv($self->client, &node);
		return new_node_from_plist(node);
	}
};

