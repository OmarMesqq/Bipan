package com.omarmesqq.grunfeld.data

// https://kotlinlang.org/docs/sealed-classes.html
sealed interface DeviceIdState {
    data object Loading : DeviceIdState
    data object FirstLaunch : DeviceIdState
    data class Compared(val rows: List<DeviceIdComparisonRow>) : DeviceIdState
}

data class DeviceIdComparisonRow(
    val label: String,
    val current: String,
    val previous: String
)