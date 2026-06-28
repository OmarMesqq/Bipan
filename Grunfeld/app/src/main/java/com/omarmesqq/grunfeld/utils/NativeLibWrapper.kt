package com.omarmesqq.grunfeld.utils

import android.content.Context

object NativeLibWrapper {
    external fun getDeviceData(context: Context): String
    external fun testSensors(): String
    external fun getUname(): String
    external fun testBind(): String
    external fun testListen(): String
    external fun testSendto(): String
    external fun testGetsockname(): String
    external fun testSocket(): String
    external fun testSendmsg(): String
    external fun installSigsysHandler(): Boolean
    external fun blockSigSys(): Boolean
    external fun queryProcStatus():String
    external fun getifaddrs():String
    external fun getallfds():String
    external fun getprocselfmapsFd():String
    external fun inspectLibcHooks(): String
    external fun dl_iterate_phdrTest(): String
}
