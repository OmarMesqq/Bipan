package com.omarmesqq.grunfeld.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.omarmesqq.grunfeld.repository.DataStoreRepo

class MainViewModelFactory(private val dsRepo: DataStoreRepo) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(MainViewModel::class.java)) {
            return MainViewModel(dsRepo) as T
        }
        throw IllegalArgumentException("MainViewModelFactory: unexpected ViewModel class")
    }
}