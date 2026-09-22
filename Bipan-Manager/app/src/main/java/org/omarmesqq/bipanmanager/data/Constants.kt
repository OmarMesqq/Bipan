package org.omarmesqq.bipanmanager.data

const val PACKAGE_NAME = "org.omarmesqq.bipanmanager"
const val BIPAN_TARGETS_DIR = "/data/adb/modules/bipan/targets"
const val DROIDGUARD_PKG_NAME = "com.google.android.gms.unstable"
val DEFAULT_TARGETS = listOf(
    "com.android.vending",
    "com.google.android.gms",
    DROIDGUARD_PKG_NAME
)