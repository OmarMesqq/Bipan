package org.omarmesqq.bipanmanager.data

import org.omarmesqq.bipanmanager.repository.DataStoreRepo
import org.omarmesqq.bipanmanager.repository.GetRootShellRepo
import org.omarmesqq.bipanmanager.repository.InstalledAppsRepo

data class MainViewModelInitParams(
    val repository: DataStoreRepo,
    val installedAppsRepo: InstalledAppsRepo,
    val getRootShellRepo: GetRootShellRepo
)