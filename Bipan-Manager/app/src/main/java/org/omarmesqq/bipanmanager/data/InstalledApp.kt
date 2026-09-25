package org.omarmesqq.bipanmanager.data

import android.graphics.drawable.Drawable

data class InstalledApp(
    val packageName: String,
    val label: String,
    val icon: Drawable,
    val isSystemApp: Boolean
)

data class TemplateJniCrossingStruct(
    val foo: String
)
