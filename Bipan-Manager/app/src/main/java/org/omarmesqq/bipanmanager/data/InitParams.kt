package org.omarmesqq.bipanmanager.data

import org.omarmesqq.bipanmanager.repository.DataStoreRepo
import org.omarmesqq.bipanmanager.repository.GetRootShellRepo
import org.omarmesqq.bipanmanager.repository.InstalledAppsRepo
import org.omarmesqq.bipanmanager.viewmodel.MainViewModel

data class MainViewModelInitParams(
    val repository: DataStoreRepo,
    val installedAppsRepo: InstalledAppsRepo,
    val getRootShellRepo: GetRootShellRepo
)

data class AppInitParams(
    val mainViewModel: MainViewModel,
    val currentTargets: Set<String>
)
