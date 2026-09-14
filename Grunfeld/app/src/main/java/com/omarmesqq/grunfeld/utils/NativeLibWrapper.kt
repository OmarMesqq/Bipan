package com.omarmesqq.grunfeld.utils

object NativeLibWrapper {
    external fun sysPropsGet(propName: String): String
    external fun sysPropsReadWithNullName(propName: String): String
    external fun sysPropsRead(propName: String): String
    external fun sysPropsReadCb(propName: String): String

    external fun testSensors(): String

    external fun unameInlineAsm(): String
    external fun unameRawAsmSyscall(): String
    external fun unameSyscallLibcWrapper(): String
    external fun unameBionic(): String
    external fun testGetsockname(): String

    external fun getMediaDrmIdNative(): String
    external fun testOpenFileAndReadLink(filenames: Array<String>): String
    external fun dlIteratePhdrTest(): String
    external fun testStatfsToHosts(): String
    external fun testForkExec(progname: String): String

    external fun scanProcSelfMaps(): String
    external fun scanProcSelfSmaps(): String
    external fun scanMountPoint(mountpoint: String): String

    external fun testFaccessat(filenames: Array<String>): String
    external fun testFstat(filenames: Array<String>): String
    external fun testNewfstatat(filenames: Array<String>): String
    external fun testStatx(filenames: Array<String>): String

    external fun installSigsysHandler(): Boolean
    external fun triggerSigsysViolation(): Boolean
    external fun blockSigSys(): Boolean
    external fun raiseSegv()
    external fun raiseAbrt()
    external fun raiseTrap()
    external fun raiseQuit()
}
