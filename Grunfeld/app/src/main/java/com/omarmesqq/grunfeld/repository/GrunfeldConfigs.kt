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

class GrunfeldConfigs(private val context: Context) {
    private val isFlagSecureEnabledKey = booleanPreferencesKey("FLAG_SECURE_KEY")

    val isFlagSecureEnabledKeyFlow: Flow<Boolean> = context.dataStore.data
        .map { preferences ->
            preferences[isFlagSecureEnabledKey] ?: false
    }

    suspend fun toggleIsFlagSecure() {
        val currentState = isFlagSecureEnabledKeyFlow.first()
        context.dataStore.edit { prefs ->
            prefs[isFlagSecureEnabledKey] = !currentState
        }
    }
}