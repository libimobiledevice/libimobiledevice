#! /usr/bin/env python

from libiphone.iPhone import *

# get msync client
def GetMobileSyncClient() :
    phone = iPhone()
    if not phone.init_device() :
        print "Couldn't find device, is it connected ?\n"
        return None
    lckd = phone.get_lockdown_client()
    if not lckd :
        print "Failed to start lockdown service.\n"
        return None
    msync = lckd.get_mobile_sync_client()
    if not msync :
        print "Failed to start mobilesync service.\n"
        return None
    return msync


msync = GetMobileSyncClient()

if not msync :
    exit(1)

array = PListNode(PLIST_ARRAY)
array.add_sub_string("SDMessageSyncDataClassWithDevice")
array.add_sub_string("com.apple.Contacts");
array.add_sub_string("---");
array.add_sub_string("2009-01-13 22:25:58 +0100");
array.add_sub_uint(106);
array.add_sub_string("___EmptyParameterString___");

msync.send(array)
array = msync.receive()
print array.to_xml()



