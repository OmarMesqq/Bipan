package com.omarmesqq.grunfeld.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.omarmesqq.grunfeld.data.MainViewModelInitParams

class MainViewModelFactory(val initParams: MainViewModelInitParams) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(MainViewModel::class.java)) {
            return MainViewModel(initParams) as T
        }
        throw IllegalArgumentException("MainViewModelFactory: unexpected ViewModel class")
    }
}