package org.omarmesqq.bipanmanager.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
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
    private val _isFirstLaunch = MutableStateFlow<Boolean?>(null)
    private val _appList = MutableStateFlow<List<InstalledApp>?>(null)
    private val _rootShell = MutableStateFlow<Shell?>(null)
    private val _currentTargets = MutableStateFlow<Set<String>>(emptySet())

    val isFirstLaunch: Flow<Boolean?> = _isFirstLaunch
    val appList = _appList.asStateFlow()
    val isAppReady: Flow<Boolean> = _isAppReady
    val currentTargets = _currentTargets.asStateFlow()

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

    suspend fun refreshAll() {
        withContext(Dispatchers.IO + CoroutineName("$TAG/refreshAll")) {
            profileCoroutine(CoroutineMode.SUSPEND_FUN) {
                refreshTargets()
                refreshAppList()
            }
        }
        joti("Refreshed targets and apps", TAG, null, true)
    }

    override fun onCleared() {
        super.onCleared()
        jotd("onCleared: VM destroyed", TAG)
    }
}