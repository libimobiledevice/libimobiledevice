#! /usr/bin/env python

from iphone import *
from plist import *

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
    msync = lckd.get_mobilesync_client()
    if not msync :
        print "Failed to start mobilesync service.\n"
        return None
    return msync


msync = GetMobileSyncClient()

if not msync :
    exit(1)

a = Array()
a.append( String("SDMessageSyncDataClassWithDevice") )
a.append( String("") )
a.append( String("com.apple.Contacts") )
a.append( String("---") )
a.append( String("2009-01-13 22:25:58 +0100") )
a.append( Integer(106) )
a.append( String("___EmptyParameterString___") )

msync.send(a)
a = msync.receive()
print a.to_xml()



