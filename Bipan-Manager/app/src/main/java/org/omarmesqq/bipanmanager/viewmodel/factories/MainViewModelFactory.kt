package org.omarmesqq.bipanmanager.viewmodel.factories

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import org.omarmesqq.bipanmanager.data.MainViewModelInitParams
import org.omarmesqq.bipanmanager.viewmodel.MainViewModel

private const val TAG = "MainViewModelFactory"
class MainViewModelFactory(private val initParams: MainViewModelInitParams) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(MainViewModel::class.java)) {
            return MainViewModel(initParams) as T
        }
        throw IllegalArgumentException("$TAG: unexpected ViewModel class: ${modelClass.name}")
    }
}