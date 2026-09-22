package org.omarmesqq.bipanmanager

import android.annotation.SuppressLint
import android.app.Application
import android.content.Intent
import android.content.IntentFilter
import android.os.StrictMode
import android.os.StrictMode.ThreadPolicy
import android.os.StrictMode.VmPolicy
import androidx.core.content.ContextCompat
import org.omarmesqq.bipanmanager.receivers.PackageUpdateReceiver
import org.omarmesqq.bipanmanager.repository.DataStoreRepo
import org.omarmesqq.bipanmanager.repository.RootShellRepo
import org.omarmesqq.bipanmanager.singletons.Darwin
import org.omarmesqq.bipanmanager.singletons.Darwin.jote
import org.omarmesqq.bipanmanager.singletons.Darwin.jotw

private const val TAG = "MainApplication"

class MainApplication : Application() {
    companion object {
        init {
            System.loadLibrary("nativeTemplate")
        }
    }

    private val packageUpdateReceiver = PackageUpdateReceiver(RootShellRepo())

    lateinit var dataStoreRepo: DataStoreRepo
        private set

    override fun onCreate() {
        super.onCreate()
        Darwin.init(this)

        if (BuildConfig.DEBUG) {
            enableStrictMode()
        }

        dataStoreRepo = DataStoreRepo(this)
        registerPackageAddedReceiver()
    }

    private fun registerPackageAddedReceiver() {
        val filter = IntentFilter(Intent.ACTION_PACKAGE_ADDED).apply {
            addDataScheme("package")
        }
        ContextCompat.registerReceiver(
            this,
            packageUpdateReceiver,
            filter,
            ContextCompat.RECEIVER_EXPORTED
        )
    }

    override fun onLowMemory() {
        super.onLowMemory()
        jotw("onLowMemory", TAG)
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        // Clean up resources that can efficiently and quickly be re-built if the user returns to the app
        if (level >= TRIM_MEMORY_BACKGROUND) {
            jotw("onTrimMemory: on LRU list", TAG)
        }
        // Large allocations with the UI should be released
        else if (level >= TRIM_MEMORY_UI_HIDDEN) {
            jotw("onTrimMemory: no longer showing UI", TAG)
        } else {
            jote("onTrimMemory: unexpected level: $level", TAG)
        }
    }

    @SuppressLint("NewApi")
    private fun enableStrictMode() {
        StrictMode.setThreadPolicy(
            ThreadPolicy.Builder()
                .detectCustomSlowCalls()
                .detectDiskReads()
                .detectDiskWrites()
                .detectResourceMismatches()
                .detectUnbufferedIo()
                .detectExplicitGc()
                .penaltyLog()
                .build()
        )

        StrictMode.setVmPolicy(
            VmPolicy.Builder()
                .detectContentUriWithoutPermission()
                .detectCredentialProtectedWhileLocked()
                .detectFileUriExposure()
                .detectImplicitDirectBoot()
                .detectIncorrectContextUse()
                .detectLeakedClosableObjects()
                .detectLeakedRegistrationObjects()
                .detectLeakedSqlLiteObjects()
                .permitNonSdkApiUsage() // LeakCanary violates this
                .detectUnsafeIntentLaunch()
                .detectActivityLeaks()
                .detectBlockedBackgroundActivityLaunch()
                .penaltyLog()
                .build()
        )
    }
}