package com.omarmesqq.grunfeld.utils

object NativeLibWrapper {
    external fun getUname(): String
    external fun installSigsysHandler(): Boolean
    external fun testFileSystemProbes()
    external fun testNetworkIdentity()
    external fun testNetworkLeaks()
    external fun removeBipan()
}
