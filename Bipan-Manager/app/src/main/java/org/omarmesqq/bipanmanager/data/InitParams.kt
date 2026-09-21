package org.omarmesqq.bipanmanager.data

import org.omarmesqq.bipanmanager.repository.InstalledAppsRepository
import org.omarmesqq.bipanmanager.repository.ManagerConfig

data class MainViewModelInitParams(
    val repository: ManagerConfig,
    val installedAppsRepository: InstalledAppsRepository
)