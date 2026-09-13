package com.omarmesqq.grunfeld.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.omarmesqq.grunfeld.repository.GrunfeldConfigs
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class MainViewModel(private val repository: GrunfeldConfigs) : ViewModel() {
    private val _isAppReady = MutableStateFlow(false)
    private val _isFlagSecureEnabled = MutableStateFlow(false)


    val isAppReady = _isAppReady.asStateFlow()
    val isFlagSecureEnabled = _isFlagSecureEnabled.asStateFlow()

    init {
        viewModelScope.launch {
            _isAppReady.value = true
            repository.flagSecureEnabledFlow.collect { isEnabled ->
                _isFlagSecureEnabled.value = isEnabled
            }
        }
    }
}