package com.omarmesqq.grunfeld.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.omarmesqq.grunfeld.data.DeviceIdState
import com.omarmesqq.grunfeld.data.MainViewModelInitParams
import com.omarmesqq.grunfeld.data.RootCheckResult
import com.omarmesqq.grunfeld.data.SettingsGlobalField
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch


class MainViewModel(val initParams: MainViewModelInitParams) : ViewModel() {
    private val _isAppReady = MutableStateFlow(false)
    private val _isFlagSecureEnabled = MutableStateFlow(false)
    private val _deviceIdsState = MutableStateFlow<DeviceIdState>(DeviceIdState.Loading)
    private val _settingsGlobalFields = MutableStateFlow<List<SettingsGlobalField>>(emptyList())

    val isAppReady = _isAppReady.asStateFlow()
    val isFlagSecureEnabled = _isFlagSecureEnabled.asStateFlow()
    val deviceIdsState = _deviceIdsState.asStateFlow()
    val settingsGlobalFields = _settingsGlobalFields.asStateFlow()

    val isRooted: StateFlow<RootCheckResult> = initParams.app.rootBeerResult

    init {
        viewModelScope.launch {
            val dsRepo = initParams.dataStoreRepo
            val deviceIdRepo = initParams.deviceIdRepo
            val settingsGlobalRepo = initParams.settingsGlobalRepo

            // FLAG_SECURE on/off
            _isFlagSecureEnabled.value = dsRepo.flagSecureEnabledFlow.first()

            // Device IDs (SSAID and MediaDRM)
            _deviceIdsState.value = deviceIdRepo.getDeviceIds()

            // `Settings.Global`
            _settingsGlobalFields.value = settingsGlobalRepo.getFields()

            // Signal UI app's ready!
            _isAppReady.value = true
        }
    }
}