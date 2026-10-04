package org.omarmesqq.bipanmanager

import android.content.Context
import org.omarmesqq.bipanmanager.data.DataStoreRepoInitParams
import org.omarmesqq.bipanmanager.repository.DataStoreRepo
import org.omarmesqq.bipanmanager.repository.RootShellRepo
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd

private const val TAG = "AppContainer"
class AppContainer(private val ctx: Context) {
    init {
        jotd("Instantiated: ${this.hashCode()}", TAG)
    }
    
    val dataStoreRepo by lazy {
        val ip = DataStoreRepoInitParams(ctx as MainApplication)
        DataStoreRepo(ip)
    }

    val rootShellRepo by lazy {
        RootShellRepo()
    }

}