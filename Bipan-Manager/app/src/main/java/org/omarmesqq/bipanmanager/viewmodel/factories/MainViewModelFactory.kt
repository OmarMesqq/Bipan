package org.omarmesqq.bipanmanager.viewmodel.factories

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import org.omarmesqq.bipanmanager.repository.ManagerConfig
import org.omarmesqq.bipanmanager.viewmodel.MainViewModel

class MainViewModelFactory(private val repository: ManagerConfig) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(MainViewModel::class.java)) {
            return MainViewModel(repository) as T
        }
        throw IllegalArgumentException("MainViewModelFactory: unexpected ViewModel class")
    }
}