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
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.singletons.Darwin.jote
import org.omarmesqq.bipanmanager.utils.CoroutineMode
import org.omarmesqq.bipanmanager.utils.profileCoroutine

private const val TAG = "MainViewModel"

class MainViewModel(private val initParams: MainViewModelInitParams) : ViewModel() {
    private val _shouldShowUi = MutableStateFlow(false)
    private val _isAppReady = MutableStateFlow(false)
    private val _isFirstLaunch = MutableStateFlow(true)
    private val _appList = MutableStateFlow<List<InstalledApp>?>(null)
    private val _rootShell = MutableStateFlow<Shell?>(null)
    private val _currentTargets = MutableStateFlow<Set<String>>(emptySet())

    // Blocks `App` Compose until everything UI-wise is ready
    val shouldShowUi = _shouldShowUi.asStateFlow()
    // Blocks MainActivity until logic essentials are ready
    val isAppReady = _isAppReady.asStateFlow()
    val isFirstLaunch = _isFirstLaunch.asStateFlow()

    val listItems: StateFlow<List<AppListItem>?> =
        combine(_appList, _currentTargets) { apps, targets ->
            if (apps == null) return@combine null

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

                    _rootShell.value = rootShellRepo.buildAndGetFirstShell()

                    val firstLaunch = dsRepo.isFirstLaunchFlow.first()
                    _isFirstLaunch.value = firstLaunch

                    if (firstLaunch) {
                        if (rootShellRepo.createDefaultTargets()) {
                            dsRepo.toggleFirstLaunch()
                        } else {
                            jote("$TAG/init: createDefaultTargets failed", TAG)
                        }
                    }

                    refreshAll()

                    _isAppReady.value = true
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

    suspend fun refreshAll() {
        withContext(Dispatchers.IO + CoroutineName("$TAG/refreshAll")) {
            profileCoroutine(CoroutineMode.SUSPEND_FUN) {
                refreshTargets()
                refreshAppList()
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