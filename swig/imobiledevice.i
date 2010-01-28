 /* swig.i */
 %module imobiledevice
 %feature("autodoc", "1");
 %{
 /* Includes the header in the wrapper code */
 #include <libimobiledevice/libimobiledevice.h>
 #include <libimobiledevice/lockdown.h>
 #include <libimobiledevice/mobilesync.h>
 #include <plist/plist.h>
 #include <plist/plist++.h>
 #include "../src/debug.h"
 typedef struct {
	idevice_t dev;
 } idevice;

 typedef struct {
	idevice* dev;
	lockdownd_client_t client;
 } Lockdownd;

 typedef struct {
	idevice* dev;
	mobilesync_client_t client;
 } MobileSync;

//now declare funtions to handle creation and deletion of objects
void my_delete_idevice(idevice* dev);
Lockdownd* my_new_Lockdownd(idevice* device);
void my_delete_Lockdownd(Lockdownd* lckd);
MobileSync* my_new_MobileSync(Lockdownd* lckd);
PList::Node* new_node_from_plist(plist_t node);

 %}
/* Parse the header file to generate wrappers */
%include "stdint.i"
%include "cstring.i"
%include "plist/swig/plist.i"

typedef struct {
	idevice_t dev;
} idevice;

typedef struct {
	idevice* dev;
	lockdownd_client_t client;
} Lockdownd;

typedef struct {
	idevice* dev;
	mobilesync_client_t client;
} MobileSync;

%inline %{
//now define funtions to handle creation and deletion of objects


void my_delete_idevice(idevice* dev) {
	if (dev) {
		idevice_free(dev->dev);
		free(dev);
	}
}

Lockdownd* my_new_Lockdownd(idevice* device) {
	if (!device) return NULL;
	Lockdownd* client = (Lockdownd*) malloc(sizeof(Lockdownd));
	client->dev = device;
	client->client = NULL;
	if (LOCKDOWN_E_SUCCESS == lockdownd_client_new_with_handshake(device->dev , &(client->client), NULL)) {
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
	uint16_t port = 0;
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


%extend idevice {             // Attach these functions to struct idevice
	idevice() {
		idevice* device = (idevice*) malloc(sizeof(idevice));
		device->dev = NULL;
		return device;
	}

	~idevice() {
		my_delete_idevice($self);
	}

	void set_debug_level(int level) {
		idevice_set_debug_level(level);
	}

	int init_device_by_uuid(char* uuid) {
		if (IDEVICE_E_SUCCESS == idevice_new(&($self->dev), uuid))
			return 1;
		return 0;
	}

	int init_device() {
		if (IDEVICE_E_SUCCESS == idevice_new(&($self->dev), NULL))
			return 1;
		return 0;
	}

	%newobject get_uuid;
	char* get_uuid(){
		char* uuid = NULL;
		idevice_get_uuid($self->dev, &uuid);
		return uuid;
	}

	Lockdownd* get_lockdown_client() {
		return my_new_Lockdownd($self);
	}
};


%extend Lockdownd {             // Attach these functions to struct Lockdownd
	Lockdownd(idevice* device) {
		return my_new_Lockdownd(device);
	}

	~Lockdownd() {
		my_delete_Lockdownd($self);
	}

	void send(PList::Node* node) {
		lockdownd_send($self->client, node->GetPlist());
	}

	PList::Node* receive() {
		plist_t node = NULL;
		lockdownd_receive($self->client, &node);
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
		mobilesync_receive($self->client, &node);
		return new_node_from_plist(node);
	}
};

