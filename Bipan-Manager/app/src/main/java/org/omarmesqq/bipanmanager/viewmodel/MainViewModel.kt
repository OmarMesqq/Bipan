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
import org.omarmesqq.bipanmanager.utils.CoroutineMode
import org.omarmesqq.bipanmanager.utils.profileCoroutine

private const val TAG = "MainViewModel"
class MainViewModel(private val initParams: MainViewModelInitParams): ViewModel() {
    private val _isAppReady = MutableStateFlow(false)
    private val _isFirstLaunch = MutableStateFlow<Boolean?>(null)
    private val _appList = MutableStateFlow<List<InstalledApp>?>(null)
    private val _rootShell = MutableStateFlow<Shell?>(null)
    private val _isRootGranted = MutableStateFlow(false)
    private val _currentTargets = MutableStateFlow<Set<String>>(emptySet())

    val isFirstLaunch: Flow<Boolean?> = _isFirstLaunch
    val appList = _appList.asStateFlow()
    val isAppReady: Flow<Boolean> = _isAppReady
    val isRootGranted = _isRootGranted
    val currentTargets = _currentTargets.asStateFlow()

    init {
        viewModelScope.launch {
            withContext(Dispatchers.IO + CoroutineName("$TAG/init")) {
                profileCoroutine(CoroutineMode.LAUNCH) {
                    _isFirstLaunch.value = initParams.dataStoreRepo.isFirstLaunchFlow.first()
                    _appList.value = initParams.installedAppsRepo.getInstalledApps()
                    _rootShell.value = initParams.rootShellRepo.getRootShell()
                    _isRootGranted.value = _rootShell.value!!.isRoot
                    refreshTargets()
                    _isAppReady.value = true
                }
            }
        }
    }

    fun refreshTargets() {
        _currentTargets.value = initParams.rootShellRepo.getBipanTargetsDir().toSet()
    }

    fun refreshAppList() {
        viewModelScope.launch(Dispatchers.IO) {
            _appList.value = initParams.installedAppsRepo.getInstalledApps()
        }
    }

    suspend fun refreshAll() {
        withContext(Dispatchers.IO) {
            _currentTargets.value = initParams.rootShellRepo.getBipanTargetsDir().toSet()
            _appList.value = initParams.installedAppsRepo.getInstalledApps()
        }
    }

    override fun onCleared() {
        super.onCleared()
        jotd("onCleared: VM destroyed", TAG)
    }
}