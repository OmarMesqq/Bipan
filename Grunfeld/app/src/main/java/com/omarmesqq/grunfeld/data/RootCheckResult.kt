package com.omarmesqq.grunfeld.data

enum class RootCheckResult(val actualValue: Boolean?) {
    LOADING(null),
    ROOTED(true),
    NOT_ROOTED(false),
}