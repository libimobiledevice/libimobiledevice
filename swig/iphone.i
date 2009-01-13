 /* swig.i */
 %module(package="libiphone") iPhone
 %{
 /* Includes the header in the wrapper code */
 #include <libiphone/libiphone.h>
 #include <plist/plist.h>

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
//typedef struct {
//	plist_t node;
//} PListNode;
 %}
/* Parse the header file to generate wrappers */
%include "plist/swig/plist.i"
 //(module="libplist.PList")override module name until package path gets fixed in swig (1.3.37)

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
		if (IPHONE_E_SUCCESS == iphone_get_device ( &phone->dev ))
			return phone;
		free(phone);
		return NULL;
	}

	~iPhone() {
		iphone_free_device ( $self->dev );
		free($self);
	}

	Lockdownd* GetLockdownClient() {
		Lockdownd* client = (Lockdownd*) malloc(sizeof(Lockdownd));
		client->client = NULL;
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
		if (IPHONE_E_SUCCESS == iphone_lckd_new_client ( phone->dev , &client->client)) {
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
		iphone_msync_new_client ( phone->dev, src_port, dst_port, &client->client);
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
		PListNode* node = NULL;
		iphone_msync_recv($self->client, &(node->node));
		return node;
	}
};

