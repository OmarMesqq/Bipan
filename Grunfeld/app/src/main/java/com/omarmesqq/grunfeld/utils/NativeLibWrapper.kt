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
    external fun testGetsocknameV4(): String
    external fun testSensors(): String
    external fun testDlIteratePhdr(): String
    external fun getMediaDrmIdNative(): String
    external fun testForkExec(progname: String): String

    external fun scanProcSelfMaps(mapsPath: String): String
    external fun scanProcSelfSmaps(smapsPath: String): String
    external fun scanMountPoint(mountpoint: String): String

    external fun getFdSymlink(fd: Int): String
    external fun openFileNative(path: String): Int

    external fun testFaccessat(filenames: Array<String>): String
    external fun testFstat(filename: String): StatResult
    external fun testNewfstatat(filename:String): StatResult
    external fun testStatx(): String
}
