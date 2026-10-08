package org.omarmesqq.bipanmanager.data

import org.omarmesqq.bipanmanager.MainApplication
import org.omarmesqq.bipanmanager.repository.DataStoreRepo
import org.omarmesqq.bipanmanager.repository.InstalledAppsRepo
import org.omarmesqq.bipanmanager.repository.RootShellRepo
import org.omarmesqq.bipanmanager.viewmodel.MainViewModel


data class DataStoreRepoInitParams(
    val app: MainApplication
)

data class InstalledAppsRepoInitParams(
    val app: MainApplication
)

data class MainViewModelInitParams(
    val dataStoreRepo: DataStoreRepo,
    val installedAppsRepo: InstalledAppsRepo,
    val rootShellRepo: RootShellRepo
)

data class AppInitParams(
    val mainViewModel: MainViewModel,
    val isRooted: Boolean,
    val bipanFolderExists: Boolean,
    val isFirstLaunch: Boolean
)
