package com.omarmesqq.grunfeld.repository

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.omarmesqq.grunfeld.data.DataStoreRepoInitParams
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "settings")

private const val IS_FLAG_SECURE_ENABLED_DEFAULT = true
private const val UNIQUE_DEVICE_ID_DEFAULT = ""

class DataStoreRepo(initParams: DataStoreRepoInitParams) {
    private val context = initParams.context
    private val isFirstLaunchPref = booleanPreferencesKey("IS_FIRST_LAUNCH")
    private val flagSecureEnabledPref = booleanPreferencesKey("IS_FLAG_SECURE_ENABLED")
    private val deviceidSsaidPref = stringPreferencesKey("DEVICE_SSAID")
    private val deviceidDrmIdPref = stringPreferencesKey("DEVICE_DRM_ID")
    private val deviceidDrmIdNdkPref = stringPreferencesKey("DEVICE_DRM_ID_NDK")

    val flagSecureEnabledFlow: Flow<Boolean> = context.dataStore.data
        .map { preferences ->
            preferences[flagSecureEnabledPref] ?: IS_FLAG_SECURE_ENABLED_DEFAULT
        }

    val isFirstLaunchFlow: Flow<Boolean> = context.dataStore.data
        .map { preferences ->
            preferences[isFirstLaunchPref] ?: true
        }

    val ssaidFlow: Flow<String> = context.dataStore.data
        .map { preferences ->
            preferences[deviceidSsaidPref] ?: UNIQUE_DEVICE_ID_DEFAULT
        }

    val drmIdFlow: Flow<String> = context.dataStore.data
        .map { preferences ->
            preferences[deviceidDrmIdPref] ?: UNIQUE_DEVICE_ID_DEFAULT
        }

    val drmIdNdkFlow: Flow<String> = context.dataStore.data
        .map { preferences ->
            preferences[deviceidDrmIdNdkPref] ?: UNIQUE_DEVICE_ID_DEFAULT
        }

    suspend fun toggleFlagSecure() {
        val currentState = flagSecureEnabledFlow.first()
        context.dataStore.edit { prefs ->
            prefs[flagSecureEnabledPref] = !currentState
        }
    }

    suspend fun toggleFirstLaunch() {
        context.dataStore.edit { prefs ->
            prefs[isFirstLaunchPref] = false
        }
    }

    suspend fun updateDeviceIds(ssaid: String, drmId: String, drmIdNdk: String) {
        context.dataStore.edit { prefs ->
            prefs[deviceidSsaidPref] = ssaid
            prefs[deviceidDrmIdPref] = drmId
            prefs[deviceidDrmIdNdkPref] = drmIdNdk
        }
    }
}