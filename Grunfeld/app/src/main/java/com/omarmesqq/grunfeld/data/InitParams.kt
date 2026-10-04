package com.omarmesqq.grunfeld.data

import android.content.ContentResolver
import android.content.Context
import com.omarmesqq.grunfeld.MainApplication
import com.omarmesqq.grunfeld.repository.DataStoreRepo
import com.omarmesqq.grunfeld.repository.DeviceIdRepo
import com.omarmesqq.grunfeld.repository.SettingsGlobalRepo

data class MainViewModelInitParams(
    val app: MainApplication,
    val dataStoreRepo: DataStoreRepo,
    val deviceIdRepo: DeviceIdRepo,
    val settingsGlobalRepo: SettingsGlobalRepo
)

data class DataStoreRepoInitParams(
    val context: Context
)

data class DeviceIdRepoInitParams(
    val cr: ContentResolver,
    val dataStoreRepo: DataStoreRepo,
)

data class SettingsGlobalRepoInitParams(
    val cr: ContentResolver
)