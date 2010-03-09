 /* swig.i */
 %module imobiledevice
 %feature("autodoc", "1");
 %{
 /* Includes the header in the wrapper code */
 #include <libimobiledevice/libimobiledevice.h>
 #include <libimobiledevice/lockdown.h>
 #include <libimobiledevice/mobilesync.h>
 #include <libimobiledevice/notification_proxy.h>
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

typedef struct {
    idevice* dev;
    np_client_t client;
} NotificationProxy;

//now declare funtions to handle creation and deletion of objects
static void my_delete_idevice(idevice* dev) {
	if (dev) {
		idevice_free(dev->dev);
		free(dev);
	}
}

static Lockdownd* my_new_Lockdownd(idevice* device) {
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

static void my_delete_Lockdownd(Lockdownd* lckd) {
    if (lckd) {
        lockdownd_client_free(lckd->client);
        free(lckd);
    }
}

static MobileSync* my_new_MobileSync(Lockdownd* lckd) {
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

static NotificationProxy* my_new_NotificationProxy(Lockdownd* lckd) {
    if (!lckd || !lckd->dev) return NULL;
    NotificationProxy* client = NULL;
    uint16_t port = 0;
	if (LOCKDOWN_E_SUCCESS == lockdownd_start_service(lckd->client, "com.apple.mobile.notification_proxy", &port)) {
        client = (NotificationProxy*) malloc(sizeof(NotificationProxy));
        client->dev = lckd->dev;
        client->client = NULL;
		np_client_new(lckd->dev->dev, port, &(client->client));
    }
    return client;
}

static PList::Node* new_node_from_plist(plist_t node)
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

#ifdef SWIGPYTHON
static void NotificationProxyPythonCallback(const char *notification, void* user_data) {
    PyObject *func, *arglist;

    func = (PyObject *) user_data;
    arglist = Py_BuildValue("(s)",notification);

    PyEval_CallObject(func, arglist);

    Py_DECREF(arglist);
}
#endif
 %}

/* Parse the header file to generate wrappers */
%include "stdint.i"
%include "cstring.i"
%include "plist/swig/plist.i"

/* This needs to be here since if it's after
 * the structs, SWIG won't pick it up for %extend
 */
#ifdef SWIGPYTHON
%typemap(in) (PyObject *pyfunc) {
    if (!PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Need a callable object!");
        return NULL;
    }
    $1 = $input;
}
%typemap(in) (const char **string_list) {
    /* Check if it's a list */
    if (PyList_Check($input)) {
        int size = PyList_Size($input);
        int i = 0;
        $1 = (char **) malloc((size+1)*sizeof(char *));
        for (i = 0; i < size; i++) {
            PyObject *o = PyList_GetItem($input,i);
            if (PyString_Check(o)) {
                $1[i] = PyString_AsString(PyList_GetItem($input,i));
            } else {
                PyErr_SetString(PyExc_TypeError,"List must contain strings");
                free($1);
                return NULL;
            }
        }
        $1[i] = 0;
    } else if (PyTuple_Check($input)) {
        int size = PyTuple_Size($input);
        int i = 0;
        $1 = (char **) malloc((size+1)*sizeof(char *));
        for (i = 0; i < size; i++) {
            PyObject *o = PyTuple_GetItem($input,i);
            if (PyString_Check(o)) {
                $1[i] = PyString_AsString(PyTuple_GetItem($input,i));
            } else {
                PyErr_SetString(PyExc_TypeError,"List must contain strings");
                free($1);
                return NULL;
            }
        }
        $1[i] = 0;
    } else {
        PyErr_SetString(PyExc_TypeError, "not a list or tuple");
        return NULL;
    }
}
%typemap(freearg) (const char **string_list) {
    free((char *) $1);
}
#endif

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

typedef struct {
    idevice* dev;
    np_client_t client;
} NotificationProxy;


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

    NotificationProxy* get_notification_proxy_client() {
        return my_new_NotificationProxy($self);
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

#define NP_SYNC_WILL_START           "com.apple.itunes-mobdev.syncWillStart"
#define NP_SYNC_DID_START            "com.apple.itunes-mobdev.syncDidStart"
#define NP_SYNC_DID_FINISH           "com.apple.itunes-mobdev.syncDidFinish"
#define NP_SYNC_LOCK_REQUEST         "com.apple.itunes-mobdev.syncLockRequest"

%extend NotificationProxy {
    NotificationProxy(Lockdownd* lckd) {
        return my_new_NotificationProxy(lckd);
    }

    ~NotificationProxy() {
        np_client_free($self->client);
        free($self);
    }

    int16_t post_notification(const char* notification) {
        return np_post_notification($self->client, notification);
    }

    int16_t observe_notification(const char* notification) {
        return np_observe_notification($self->client, notification);
    }

    int16_t observe_notifications(const char** string_list) {
        return np_observe_notifications($self->client, string_list);
    }
};

#ifdef SWIGPYTHON
%extend NotificationProxy {
    int16_t set_callback(PyObject *pyfunc) {
        int16_t res;
        res = np_set_notify_callback($self->client, NotificationProxyPythonCallback, (void *) pyfunc);
        Py_INCREF(pyfunc);
        return res;
    }
};
#endif
