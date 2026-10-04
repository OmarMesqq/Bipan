package com.omarmesqq.grunfeld

import android.content.Context
import com.omarmesqq.grunfeld.data.DataStoreRepoInitParams
import com.omarmesqq.grunfeld.data.DeviceIdRepoInitParams
import com.omarmesqq.grunfeld.repository.DataStoreRepo
import com.omarmesqq.grunfeld.repository.DeviceIdRepo

class AppContainer(private val ctx: Context) {
    val dataStoreRepo by lazy {
        val ip = DataStoreRepoInitParams(ctx)
        DataStoreRepo(ip)
    }

    val deviceIdRepo by lazy {
        val ip = DeviceIdRepoInitParams(ctx.contentResolver, dataStoreRepo)
        DeviceIdRepo(ip)
    }

}