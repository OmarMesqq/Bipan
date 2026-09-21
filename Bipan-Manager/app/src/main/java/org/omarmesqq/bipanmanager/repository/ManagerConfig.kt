package org.omarmesqq.bipanmanager.repository

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.omarmesqq.bipanmanager.utils.CoroutineMode
import org.omarmesqq.bipanmanager.utils.profileCoroutine

val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "settings")

class ManagerConfig (private val ctx: Context) {
    private val isFirstLaunchPref = booleanPreferencesKey("IS_FIRST_LAUNCH")

    val isFirstLaunchFlow: Flow<Boolean> = ctx.dataStore.data
        .map { preferences ->
            preferences[isFirstLaunchPref] ?: true
        }

    suspend fun toggleFirstLaunch() {
        profileCoroutine(CoroutineMode.SUSPEND_FUN) {
            ctx.dataStore.edit { prefs ->
                prefs[isFirstLaunchPref] = false
            }
        }
    }
}