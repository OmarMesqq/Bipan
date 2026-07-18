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
    external fun triggerSigsysViolation(): Boolean
    external fun blockSigSys(): Boolean
    external fun queryProcStatus():String
    external fun getifaddrs():String
    external fun getallfds():String
    external fun testOpenFileAndReadLink(filenames: Array<String>): String
    external fun inspectHooks(): String
    external fun dl_iterate_phdrTest(): String
    external fun testProcSelfAuxv(): String
    external fun testProcSelfTask(): String
    external fun testForkExec(progname: String): String
    external fun scanProcSelfMaps(): String
    external fun testFaccessat(filenames: Array<String>): String
    external fun testFstat(filenames: Array<String>): String
    external fun testStatfs(filenames: Array<String>): String
    external fun testFstatfs(filenames: Array<String>): String
    external fun testNewfstatat(filenames: Array<String>): String
    external fun testStatx(filenames: Array<String>): String
}
