package com.omarmesqq.grunfeld.utils

/**
 * Crosses JNI boundary to get data on files
 * using `fstat` and `newfstatat`
 */
data class StatResult(
    val dev: Long,
    val ino: Long,
    val size: Long,
    val blkSiz: Long,
    val blksAllocated: Long,
    val accessTime: String,
    val modTime: String,
    val statusChTime: String,
)

object NativeLibWrapper {
    external fun sysPropsGet(propName: String): String
    external fun sysPropsReadWithNullName(propName: String): String
    external fun sysPropsRead(propName: String): String
    external fun sysPropsReadCb(propName: String): String

    external fun unameInlineAsm(): String
    external fun unameRawAsmSyscall(): String
    external fun unameSyscallLibcWrapper(): String
    external fun unameBionic(): String

    external fun testGetsocknameV4(): String
    external fun testGetsocknameV6(): String

    external fun testSensors(): String
    external fun getMediaDrmIdNative(): String
    external fun testForkExec(progname: String): String

    external fun scanProcSelfMaps(): String
    external fun scanProcSelfSmaps(): String
    external fun dlIteratePhdrTest(): String
    external fun scanMountPoint(mountpoint: String): String

    external fun testFaccessat(filenames: Array<String>): String
    external fun testFstat(filename: String): StatResult
    external fun testNewfstatat(filename:String): StatResult
    external fun testStatx(): String
    external fun testStatfsToHosts(): String

    external fun installSigsysHandler(): Boolean
    external fun triggerSigsysViolation(): Boolean
    external fun blockSigSys(): Boolean
    external fun raiseSegv()
    external fun raiseAbrt()
    external fun raiseTrap()
    external fun raiseQuit()
}
