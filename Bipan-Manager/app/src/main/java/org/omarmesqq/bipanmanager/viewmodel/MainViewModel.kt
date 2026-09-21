package org.omarmesqq.bipanmanager.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.omarmesqq.bipanmanager.repository.ManagerConfig
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.utils.CoroutineMode
import org.omarmesqq.bipanmanager.utils.profileCoroutine

private const val TAG = "MainViewModel"
class MainViewModel(private val repository: ManagerConfig): ViewModel() {
    private val _isFirstLaunch = MutableStateFlow<Boolean?>(null)

    val isFirstLaunch = _isFirstLaunch.asStateFlow()

    init {
        viewModelScope.launch(CoroutineName("$TAG/init")) {
            profileCoroutine(CoroutineMode.LAUNCH) {
                repository.isFirstLaunchFlow.collect {
                    _isFirstLaunch.value = it
                }
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        jotd("onCleared: VM destroyed", TAG, shouldToast = true)
    }
}