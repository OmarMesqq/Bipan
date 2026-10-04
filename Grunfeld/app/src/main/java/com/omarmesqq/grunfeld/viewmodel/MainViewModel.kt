package com.omarmesqq.grunfeld.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.omarmesqq.grunfeld.data.DeviceIdComparisonRow
import com.omarmesqq.grunfeld.data.DeviceIdState
import com.omarmesqq.grunfeld.data.MainViewModelInitParams
import com.omarmesqq.grunfeld.data.RootCheckResult
import com.omarmesqq.grunfeld.utils.NativeLibWrapper
import com.omarmesqq.grunfeld.utils.getMediaDrmId
import com.omarmesqq.grunfeld.utils.getSsaid
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch


class MainViewModel(val initParams: MainViewModelInitParams) : ViewModel() {
    private val _isAppReady = MutableStateFlow(false)
    private val _isFlagSecureEnabled = MutableStateFlow(false)
    private val _deviceIdsState = MutableStateFlow<DeviceIdState>(DeviceIdState.Loading)

    val isAppReady = _isAppReady.asStateFlow()
    val isFlagSecureEnabled = _isFlagSecureEnabled.asStateFlow()
    val deviceIdsState = _deviceIdsState.asStateFlow()

    val isRooted: StateFlow<RootCheckResult> = initParams.app.rootBeerResult

    init {
        viewModelScope.launch {
            val dsRepo = initParams.dataStoreRepo
            val cr = initParams.cr

            // Whether FLAG_SECURE is enabled
            _isFlagSecureEnabled.value = dsRepo.flagSecureEnabledFlow.first()

            // Gather all device IDs
            val ssaid = getSsaid(cr)
            val drmId = getMediaDrmId()
            val drmIdNdk = NativeLibWrapper.getMediaDrmIdNative()

            // On first launch there are no values to compare to, just store them
            if (dsRepo.isFirstLaunchFlow.first()) {
                dsRepo.updateDeviceIds(ssaid, drmId, drmIdNdk)
                dsRepo.toggleFirstLaunch()
                _deviceIdsState.value = DeviceIdState.FirstLaunch
            } else {
                val rows = listOf(
                    DeviceIdComparisonRow("SSAID", ssaid, dsRepo.ssaidFlow.first()),
                    DeviceIdComparisonRow("DRM ID (Java API)", drmId, dsRepo.drmIdFlow.first()),
                    DeviceIdComparisonRow("DRM ID (NDK)", drmIdNdk, dsRepo.drmIdNdkFlow.first()),
                )
                dsRepo.updateDeviceIds(ssaid, drmId, drmIdNdk)
                _deviceIdsState.value = DeviceIdState.Compared(rows)
            }

            // Signal UI app's ready!
            _isAppReady.value = true
        }
    }
}