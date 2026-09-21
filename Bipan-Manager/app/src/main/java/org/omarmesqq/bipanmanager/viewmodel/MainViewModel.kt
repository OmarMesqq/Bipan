package org.omarmesqq.bipanmanager.viewmodel

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.omarmesqq.bipanmanager.data.InstalledApp
import org.omarmesqq.bipanmanager.repository.ManagerConfig
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.utils.CoroutineMode
import org.omarmesqq.bipanmanager.utils.profileCoroutine

private const val TAG = "MainViewModel"
class MainViewModel(private val repository: ManagerConfig, private val pm: PackageManager): ViewModel() {
    private val _isFirstLaunch = MutableStateFlow<Boolean?>(null)
    private val _appList = MutableStateFlow<List<InstalledApp>?>(null)

    val isFirstLaunch: Flow<Boolean?> = _isFirstLaunch
    val appList = _appList.asStateFlow()

    // TODO: Should run in worker thread or in main?
    init {
        viewModelScope.launch {
            withContext(Dispatchers.Default + CoroutineName("$TAG/init")) {
                profileCoroutine(CoroutineMode.LAUNCH) {
                    _isFirstLaunch.value = repository.isFirstLaunchFlow.first()

                    _appList.value = pm.getInstalledApplications(0)
                        .map { appInfo ->
                            InstalledApp(
                                appInfo.packageName,
                                appInfo.loadLabel(pm).toString(),
                                appInfo.loadIcon(pm),
                                (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                            )
                        }
                        .sortedBy { it.label.lowercase() }
                        .sortedBy { it.isSystemApp }
                }
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        jotd("onCleared: VM destroyed", TAG, shouldToast = true)
    }
}