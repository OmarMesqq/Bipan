package org.omarmesqq.bipanmanager.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
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
import org.omarmesqq.bipanmanager.data.InstalledApp
import org.omarmesqq.bipanmanager.data.MainViewModelInitParams
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.singletons.Darwin.joti
import org.omarmesqq.bipanmanager.utils.CoroutineMode
import org.omarmesqq.bipanmanager.utils.profileCoroutine

private const val TAG = "MainViewModel"

class MainViewModel(private val initParams: MainViewModelInitParams) : ViewModel() {
    private val _isAppReady = MutableStateFlow(false)
    private val _isFirstLaunch = MutableStateFlow(true)
    private val _appList = MutableStateFlow<List<InstalledApp>?>(null)
    private val _rootShell = MutableStateFlow<Shell?>(null)
    private val _currentTargets = MutableStateFlow<Set<String>>(emptySet())

    val isFirstLaunch: Flow<Boolean> = _isFirstLaunch
    val appList = _appList.asStateFlow()
    val isAppReady: Flow<Boolean> = _isAppReady
    val currentTargets = _currentTargets.asStateFlow()
    val staleTargets: StateFlow<Set<String>> = combine(_appList, _currentTargets) { apps, targets ->
        val installedPackageNames = apps?.map { it.packageName }?.toSet() ?: emptySet()
        targets - installedPackageNames
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = emptySet()
    )

    init {
        viewModelScope.launch {
            withContext(Dispatchers.IO + CoroutineName("$TAG/init")) {
                profileCoroutine(CoroutineMode.LAUNCH) {
                    val dsRepo = initParams.dataStoreRepo
                    val installedAppsRepo = initParams.installedAppsRepo
                    val rootShellRepo = initParams.rootShellRepo

                    _isFirstLaunch.value = dsRepo.isFirstLaunchFlow.first()
                    _appList.value = installedAppsRepo.getInstalledApps()
                    _rootShell.value = rootShellRepo.getRootShell()
                    _currentTargets.value = rootShellRepo.getBipanTargetsDir().toSet()

                    _isAppReady.value = true
                }
            }
        }
    }

    fun toggleJail(pkgName: String, jail: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            val success = if (jail) {
                jotd("Jailed $pkgName", TAG)
                initParams.rootShellRepo.jailApp(pkgName)
            } else {
                jotd("Unjailed $pkgName", TAG)
                initParams.rootShellRepo.unjailApp(pkgName)
            }

            if (success) {
                _currentTargets.update { targets ->
                    if (jail) targets + pkgName else targets - pkgName
                }
            }
            // On failure, we simply don't update state — UI naturally reflects
            // the unchanged (accurate) jailed status without extra rollback logic.
        }
    }

    suspend fun refreshAll() {
        withContext(Dispatchers.IO + CoroutineName("$TAG/refreshAll")) {
            profileCoroutine(CoroutineMode.SUSPEND_FUN) {
                refreshTargets()
                refreshAppList()
            }
        }
        joti("Refreshed targets and apps", TAG, null, true)
    }

    fun doesBipanDirExist(): Boolean {
        return initParams.rootShellRepo.doesBipanTargetsDirExist()
    }

    fun createDefaults(): Boolean {
        return initParams.rootShellRepo.createDefaultTargets()
    }

    private fun refreshTargets() {
        viewModelScope.launch(Dispatchers.IO + CoroutineName("$TAG/refreshTargets")) {
            profileCoroutine(CoroutineMode.LAUNCH) {
                _currentTargets.value = initParams.rootShellRepo.getBipanTargetsDir().toSet()
            }
        }
    }

    private fun refreshAppList() {
        viewModelScope.launch(Dispatchers.IO + CoroutineName("$TAG/refreshAppList")) {
            profileCoroutine(CoroutineMode.LAUNCH) {
                _appList.value = initParams.installedAppsRepo.getInstalledApps()
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        jotd("onCleared: VM destroyed", TAG)
    }
}