package com.omarmesqq.grunfeld.utils

object NativeLibWrapper {
    external fun getUname(): String
    external fun installSigsysHandler(): Boolean
    external fun testFileSystemProbes()
    external fun testBind()
    external fun testNetworkLeaks()
    external fun testSensors(): String
    external fun scanMaps(): String

    external fun removeBipan()
}
