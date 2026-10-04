package com.omarmesqq.grunfeld

import android.content.Context
import com.omarmesqq.grunfeld.data.DataStoreRepoInitParams
import com.omarmesqq.grunfeld.data.DeviceIdRepoInitParams
import com.omarmesqq.grunfeld.data.SettingsGlobalRepoInitParams
import com.omarmesqq.grunfeld.repository.DataStoreRepo
import com.omarmesqq.grunfeld.repository.DeviceIdRepo
import com.omarmesqq.grunfeld.repository.SettingsGlobalRepo

class AppContainer(private val ctx: Context) {
    val dataStoreRepo by lazy {
        val ip = DataStoreRepoInitParams(ctx)
        DataStoreRepo(ip)
    }

    val deviceIdRepo by lazy {
        val ip = DeviceIdRepoInitParams(ctx.contentResolver, dataStoreRepo)
        DeviceIdRepo(ip)
    }

    val settingsGlobalRepo by lazy {
        val ip = SettingsGlobalRepoInitParams(ctx.contentResolver)
        SettingsGlobalRepo(ip)
    }
}