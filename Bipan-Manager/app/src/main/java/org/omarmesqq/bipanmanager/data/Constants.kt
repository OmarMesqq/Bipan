package org.omarmesqq.bipanmanager.data

const val PACKAGE_NAME = "org.omarmesqq.bipanmanager"
const val BIPAN_TARGETS_DIR = "/data/adb/modules/bipan/targets"
const val DROIDGUARD_PKG_NAME = "com.google.android.gms.unstable"
val DEFAULT_TARGETS = mapOf(
    "com.android.vending" to "Play Store",
    "com.google.android.gms" to "GMS/microG",
    DROIDGUARD_PKG_NAME to "DroidGuard"
)