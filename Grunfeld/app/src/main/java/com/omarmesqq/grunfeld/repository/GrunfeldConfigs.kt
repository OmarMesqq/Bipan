package com.omarmesqq.grunfeld.repository

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "settings")

private const val IS_FLAG_SECURE_ENABLED_DEFAULT = true
private const val UNIQUE_DEVICE_ID_DEFAULT = ""


class GrunfeldConfigs(private val context: Context) {
    private val flagSecureEnabledPref = booleanPreferencesKey("IS_FLAG_SECURE_ENABLED")
    private val deviceId_SSAID_PREF = booleanPreferencesKey("DEVICE_SSAID")
    private val deviceId_GSF_ID_PREF = booleanPreferencesKey("DEVICE_GSF_ID")
    private val deviceId_DRM_ID_PREF = booleanPreferencesKey("DEVICE_DRM_ID")

    val flagSecureEnabledFlow: Flow<Boolean> = context.dataStore.data
        .map { preferences ->
            preferences[flagSecureEnabledPref] ?: IS_FLAG_SECURE_ENABLED_DEFAULT
    }

    val ssaidFlow = context.dataStore.data
        .map { preferences ->
            preferences[deviceId_SSAID_PREF] ?: UNIQUE_DEVICE_ID_DEFAULT
        }

    val gsfIdFlow = context.dataStore.data
        .map { preferences ->
            preferences[deviceId_GSF_ID_PREF] ?: UNIQUE_DEVICE_ID_DEFAULT
        }

    val drmIdFlow = context.dataStore.data
        .map { preferences ->
            preferences[deviceId_DRM_ID_PREF] ?: UNIQUE_DEVICE_ID_DEFAULT
        }

    suspend fun toggleFlagSecure() {
        val currentState = flagSecureEnabledFlow.first()
        context.dataStore.edit { prefs ->
            prefs[flagSecureEnabledPref] = !currentState
        }
    }
}