package com.omarmesqq.grunfeld.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.omarmesqq.grunfeld.repository.GrunfeldConfigs
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class MainViewModel(private val repository: GrunfeldConfigs) : ViewModel() {
    private val _isAppReady = MutableStateFlow(false)
    private val _isFlagSecureEnabled = MutableStateFlow(false)

    val isFlagSecureEnabled = _isFlagSecureEnabled.asStateFlow()
    val isAppReady = _isAppReady.asStateFlow()

    init {
        viewModelScope.launch {
            _isFlagSecureEnabled.value = repository.flagSecureEnabledFlow.first()
            _isAppReady.value = true
        }
    }
}