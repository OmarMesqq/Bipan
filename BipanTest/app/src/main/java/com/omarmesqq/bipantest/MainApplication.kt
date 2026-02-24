package com.omarmesqq.bipantest

import android.app.Application

class MainApplication: Application() {
    /**
     * Just load libgrunfeld.so in the static block
     * so we can get logcat with native info asap
     */
    companion object {
        init {
            System.loadLibrary("grunfeld")
        }
    }
}
