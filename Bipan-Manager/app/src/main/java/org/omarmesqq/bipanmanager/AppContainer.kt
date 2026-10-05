package org.omarmesqq.bipanmanager

import android.content.Context
import org.omarmesqq.bipanmanager.data.DataStoreRepoInitParams
import org.omarmesqq.bipanmanager.repository.DataStoreRepo
import org.omarmesqq.bipanmanager.repository.RootShellRepo

class AppContainer(private val ctx: Context) {
    val dataStoreRepo by lazy {
        val ip = DataStoreRepoInitParams(ctx as MainApplication)
        DataStoreRepo(ip)
    }

    val rootShellRepo by lazy {
        RootShellRepo()
    }
}