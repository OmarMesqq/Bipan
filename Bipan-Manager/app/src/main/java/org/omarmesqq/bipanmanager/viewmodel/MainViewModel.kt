package org.omarmesqq.bipanmanager.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.omarmesqq.bipanmanager.data.DROIDGUARD_PKG_NAME
import org.omarmesqq.bipanmanager.data.InstalledApp
import org.omarmesqq.bipanmanager.data.MainViewModelInitParams
import org.omarmesqq.bipanmanager.data.PACKAGE_NAME
import org.omarmesqq.bipanmanager.interfaces.AppListItem
import org.omarmesqq.bipanmanager.repository.BrokerProcess
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.utils.CoroutineMode
import org.omarmesqq.bipanmanager.utils.profileCoroutine

private const val TAG = "MainViewModel"

data class StartupState(
    val bipanFolderExists: Boolean,
    val isFirstLaunch: Boolean,
    val isRootGranted: Boolean,
)


class MainViewModel(private val initParams: MainViewModelInitParams) : ViewModel() {
    private val _startupState = MutableStateFlow<StartupState?>(null)
    private val _shouldShowUi = MutableStateFlow(false)
    private val _appList = MutableStateFlow<List<InstalledApp>?>(null)
    private val _rootShell = MutableStateFlow<Shell?>(null)
    private val _currentTargets = MutableStateFlow<Set<String>>(emptySet())
    private val _brokerProcesses = MutableStateFlow<List<BrokerProcess>>(emptyList())

    // Blocks MainActivity until logic essentials are ready
    val startupState = _startupState.asStateFlow()
    // Blocks `App` Compose until everything UI-wise is ready
    val shouldShowUi = _shouldShowUi.asStateFlow()
    val brokerProcesses = _brokerProcesses.asStateFlow()

    val listItems: StateFlow<List<AppListItem>?> =
        combine(_appList, _currentTargets) { apps, targets ->
            if (apps == null) {
                return@combine null
            }

            val installedPkgs = apps.mapTo(HashSet()) { it.packageName }

            val stale = (targets - installedPkgs)
            val droidGuard = if (DROIDGUARD_PKG_NAME in stale) {
                listOf(AppListItem.DroidGuard)
            } else emptyList()

            val orphans = stale
                .filterNot { it == DROIDGUARD_PKG_NAME }
                .sorted()
                .map(AppListItem::Orphaned)

            val installed = apps
                .filterNot { it.packageName == PACKAGE_NAME }
                .map { AppListItem.Installed(it, isJailed = it.packageName in targets) }
                .sortedByDescending { it.isJailed }
            orphans + droidGuard + installed
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)

    init {
        viewModelScope.launch {
            withContext(Dispatchers.IO + CoroutineName("$TAG/init")) {
                profileCoroutine(CoroutineMode.LAUNCH) {
                    val dsRepo = initParams.dataStoreRepo
                    val rootShellRepo = initParams.rootShellRepo

                    // App can't work without root so check this first
                    _rootShell.value = rootShellRepo.buildAndGetFirstShell()

                    // Create default targets if it's a fresh install
                    val firstLaunch = dsRepo.isFirstLaunchFlow.first()
                    if (firstLaunch) {
                        rootShellRepo.createDefaultTargets()
                        dsRepo.toggleFirstLaunch()
                    }

                    // Get packages and Bipan targets for first screen
                    refreshAppsAndTargets()

                    // Signal Activity to proceed
                    _startupState.value = StartupState(
                        bipanFolderExists = doesBipanDirExist(),
                        isFirstLaunch = firstLaunch,
                        isRootGranted = rootShellRepo.isRooted()
                    )

                    _shouldShowUi.value = true
                }
            }
        }
    }

    fun toggleJail(item: AppListItem, jail: Boolean) {
        viewModelScope.launch(Dispatchers.IO + CoroutineName("$TAG/toggleJail")) {
            profileCoroutine(CoroutineMode.LAUNCH) {
                val success = if (jail) {
                    initParams.rootShellRepo.jailApp(item.packageName)
                } else {
                    initParams.rootShellRepo.unjailApp(item.packageName)
                }

                if (success) {
                    _currentTargets.update { targets ->
                        if (jail) {
                            jotd("Jailed ${item.label}", TAG, null, true)
                            targets + item.packageName
                        } else {
                            jotd("Unjailed ${item.label}", TAG, null, true)
                            targets - item.packageName
                        }
                    }
                }
            }
        }
    }

    suspend fun fetchBipanBrokers() {
        withContext(Dispatchers.IO + CoroutineName("$TAG/fetchBipanBrokers")) {
            profileCoroutine(CoroutineMode.SUSPEND_FUN) {
                _brokerProcesses.value = initParams.rootShellRepo.getBipanBrokers()
            }
        }
    }


    suspend fun refreshAppsAndTargets() {
        withContext(Dispatchers.IO + CoroutineName("$TAG/refreshAll")) {
            profileCoroutine(CoroutineMode.SUSPEND_FUN) {
                refreshAppList()
                refreshTargets()
            }
        }
    }

    fun doesBipanDirExist(): Boolean {
        return initParams.rootShellRepo.doesBipanTargetsDirExist()
    }

    private suspend fun refreshTargets() {
        withContext(Dispatchers.IO + CoroutineName("$TAG/refreshTargets")) {
            profileCoroutine(CoroutineMode.SUSPEND_FUN) {
                _currentTargets.value = initParams.rootShellRepo.getBipanTargetsDir().toSet()
            }
        }
    }

    private suspend fun refreshAppList() {
        withContext(Dispatchers.IO + CoroutineName("$TAG/refreshAppList")) {
            profileCoroutine(CoroutineMode.SUSPEND_FUN) {
                _appList.value = initParams.installedAppsRepo.getInstalledApps()
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        jotd("onCleared: VM destroyed", TAG)
    }
}