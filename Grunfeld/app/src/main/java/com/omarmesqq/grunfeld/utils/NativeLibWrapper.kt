package com.omarmesqq.grunfeld.utils

import android.content.Context

object NativeLibWrapper {
    external fun getDeviceData(context: Context): String
    external fun getUname(): String

    external fun testFileSystemProbes()
    external fun testBind(): String
    external fun testSendto(): String
    external fun testGetsockname(): String
    external fun testSocket(): String
    external fun testSensors(): String
    external fun scanMaps(): String

    external fun scanDevProperties()
    external fun installSigsysHandler(): Boolean

    external fun blockSigSys(): Boolean
}
