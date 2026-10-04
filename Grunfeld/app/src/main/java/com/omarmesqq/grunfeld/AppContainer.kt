package com.omarmesqq.grunfeld

import android.content.Context
import com.omarmesqq.grunfeld.repository.DataStoreRepo

class AppContainer(private val ctx: Context) {
    val dataStoreRepo by lazy { DataStoreRepo(ctx) }
}