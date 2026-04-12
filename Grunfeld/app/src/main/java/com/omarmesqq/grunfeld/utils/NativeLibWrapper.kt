package com.omarmesqq.grunfeld.utils

object NativeLibWrapper {
    external fun getUname(): String
    external fun installSigsysHandler(): Boolean
}
