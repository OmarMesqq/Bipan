package org.omarmesqq.bipanmanager.data

const val PACKAGE_NAME = "org.omarmesqq.bipanmanager"
const val BIPAN_TARGETS_DIR = "/data/adb/modules/bipan/targets"
val DEFAULT_TARGETS = mapOf(
    "com.android.vending" to "Play Store",
    "com.google.android.gms" to "GMS/microG",
    "com.google.android.gms.unstable" to "DroidGuard"
)