#! /usr/bin/env python

from libiphone.iPhone import *

# get msync client
def GetMobileSyncClient() :
    phone = iPhone()
    if not phone.InitDevice() :
        print "Couldn't find device, is it connected ?\n"
        return None
    lckd = phone.GetLockdownClient()
    if not lckd :
        print "Failed to start lockdown service.\n"
        return None
    msync = lckd.GetMobileSyncClient()
    if not msync :
        print "Failed to start mobilesync service.\n"
        return None
    return msync


msync = GetMobileSyncClient()

if not msync :
    exit(1)

array = PListNode(PLIST_ARRAY)
array.AddSubString("SDMessageSyncDataClassWithDevice")
array.AddSubString("com.apple.Contacts");
array.AddSubString("---");
array.AddSubString("2009-01-13 22:25:58 +0100");
array.AddSubUInt(106);
array.AddSubString("___EmptyParameterString___");

msync.Send(array)
array = msync.Receive()
print array.ToXml()



