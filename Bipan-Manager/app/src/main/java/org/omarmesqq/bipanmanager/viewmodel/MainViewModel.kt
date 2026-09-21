package org.omarmesqq.bipanmanager.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import org.omarmesqq.bipanmanager.repository.ManagerConfig
import org.omarmesqq.bipanmanager.singletons.Darwin.jotd
import org.omarmesqq.bipanmanager.utils.CoroutineMode
import org.omarmesqq.bipanmanager.utils.debugCoroutine
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

private const val TAG = "MainViewModel"
class MainViewModel(private val repository: ManagerConfig): ViewModel() {
    private val _isFirstLaunch = MutableStateFlow<Boolean?>(null)

    val isFirstLaunch = _isFirstLaunch.asStateFlow()

    init {
        viewModelScope.launch(CoroutineName("$TAG/init")) {
            val start = System.currentTimeMillis()

            repository.isFirstLaunchFlow.collect {
                _isFirstLaunch.value = it
            }

            debugCoroutine(
                coroutineContext[CoroutineName],
                CoroutineMode.LAUNCH,
                System.currentTimeMillis() - start
            )

        }
    }

    override fun onCleared() {
        super.onCleared()
        jotd("onCleared: VM destroyed", TAG, shouldToast = true)
    }
}