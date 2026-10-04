package com.omarmesqq.grunfeld.repository

import android.provider.Settings.Global
import com.omarmesqq.grunfeld.data.SettingsGlobalField
import com.omarmesqq.grunfeld.data.SettingsGlobalRepoInitParams

class SettingsGlobalRepo(initParams: SettingsGlobalRepoInitParams) {
    private val _cr = initParams.cr
    fun getFields(): List<SettingsGlobalField> {
        val notFoundKey = -999

        val devSettingsOn = Global.getInt(_cr, Global.DEVELOPMENT_SETTINGS_ENABLED, notFoundKey)
        val adbEnabled = Global.getInt(_cr, Global.ADB_ENABLED, notFoundKey)
        val bootCount = Global.getInt(_cr, Global.BOOT_COUNT, notFoundKey)
        val waitForDebugger = Global.getInt(_cr, Global.WAIT_FOR_DEBUGGER, notFoundKey)

        return listOf(
            SettingsGlobalField("DEVELOPMENT_SETTINGS_ENABLED", devSettingsOn, 0),
            SettingsGlobalField("ADB_ENABLED", adbEnabled, 0),
            SettingsGlobalField("BOOT_COUNT", bootCount, 43),
            SettingsGlobalField("WAIT_FOR_DEBUGGER", waitForDebugger, 0),
        )
    }
}