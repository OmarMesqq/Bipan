package com.omarmesqq.grunfeld.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.omarmesqq.grunfeld.repository.GrunfeldConfigs

class MainViewModelFactory(
    private val repository: GrunfeldConfigs
) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(MainViewModel::class.java)) {
            return MainViewModel(repository) as T
        }
        throw IllegalArgumentException("MainViewModelFactory: unexpected ViewModel class")
    }
}