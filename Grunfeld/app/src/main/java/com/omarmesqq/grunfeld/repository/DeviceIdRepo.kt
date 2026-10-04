package com.omarmesqq.grunfeld.repository

import com.omarmesqq.grunfeld.data.DeviceIdComparisonRow
import com.omarmesqq.grunfeld.data.DeviceIdRepoInitParams
import com.omarmesqq.grunfeld.data.DeviceIdState
import com.omarmesqq.grunfeld.utils.NativeLibWrapper
import com.omarmesqq.grunfeld.utils.getMediaDrmId
import com.omarmesqq.grunfeld.utils.getSsaid
import kotlinx.coroutines.flow.first
import java.lang.ref.WeakReference

class DeviceIdRepo(initParams: DeviceIdRepoInitParams) {
    private val _cr = initParams.cr
    private val dsRepoRef = WeakReference(initParams.dataStoreRepo)

    suspend fun getDeviceIds(): DeviceIdState {
        val dsRepo = dsRepoRef.get() ?: throw Exception()

        val ssaid = getSsaid(_cr)
        val drmId = getMediaDrmId()
        val drmIdNdk = NativeLibWrapper.getMediaDrmIdNative()

        if (dsRepo.isFirstLaunchFlow.first()) {
            dsRepo.updateDeviceIds(ssaid, drmId, drmIdNdk)
            dsRepo.toggleFirstLaunch()
            return DeviceIdState.FirstLaunch
        }
        val rows = listOf(
            DeviceIdComparisonRow("SSAID", ssaid, dsRepo.ssaidFlow.first()),
            DeviceIdComparisonRow("DRM ID (Java API)", drmId, dsRepo.drmIdFlow.first()),
            DeviceIdComparisonRow("DRM ID (NDK)", drmIdNdk, dsRepo.drmIdNdkFlow.first()),
        )
        dsRepo.updateDeviceIds(ssaid, drmId, drmIdNdk)
        return DeviceIdState.Compared(rows)
    }
}