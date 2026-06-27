package com.omarmesqq.grunfeld.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import com.omarmesqq.grunfeld.repository.GrunfeldConfigs

class MainViewModel(private val repository: GrunfeldConfigs) : ViewModel() {
    private val _isReady = MutableStateFlow(false)
    val isReady: StateFlow<Boolean> = _isReady.asStateFlow()

    private val _isFlagSecureEnable = MutableStateFlow(false)
    val isFlagSecureEnable: StateFlow<Boolean> = _isFlagSecureEnable.asStateFlow()

    init {
        viewModelScope.launch {
            _isReady.value = true
            repository.isFlagSecureEnabledKeyFlow.collect { isEnabled ->
                _isFlagSecureEnable.value = isEnabled
            }
        }
    }
}