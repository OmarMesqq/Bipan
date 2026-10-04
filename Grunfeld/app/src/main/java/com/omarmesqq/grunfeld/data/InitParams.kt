package com.omarmesqq.grunfeld.data

import android.content.ContentResolver
import com.omarmesqq.grunfeld.MainApplication
import com.omarmesqq.grunfeld.repository.DataStoreRepo

data class MainViewModelInitParams(
    val dataStoreRepo: DataStoreRepo,
    val cr: ContentResolver,
    val app: MainApplication
)