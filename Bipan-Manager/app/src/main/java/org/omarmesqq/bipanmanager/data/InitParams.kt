package org.omarmesqq.bipanmanager.data

import android.content.pm.PackageManager
import org.omarmesqq.bipanmanager.MainApplication
import org.omarmesqq.bipanmanager.repository.DataStoreRepo
import org.omarmesqq.bipanmanager.repository.InstalledAppsRepo
import org.omarmesqq.bipanmanager.repository.RootShellRepo
import org.omarmesqq.bipanmanager.viewmodel.MainViewModel


data class DataStoreRepoInitParams(
    val app: MainApplication
)

data class InstalledAppsRepoInitParams(
    val pm: PackageManager
)

data class MainViewModelInitParams(
    val dataStoreRepo: DataStoreRepo,
    val installedAppsRepo: InstalledAppsRepo,
    val rootShellRepo: RootShellRepo
)

data class PackageUpdateReceiverInitParams(
    val rootShellRepo: RootShellRepo
)

data class AppInitParams(
    val mainViewModel: MainViewModel
)
