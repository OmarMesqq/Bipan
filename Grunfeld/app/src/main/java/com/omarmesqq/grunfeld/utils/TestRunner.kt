package com.omarmesqq.grunfeld.utils

object TestRunner {
    fun ensureEquals(actual: String, expected: String): Boolean {
        return actual == expected
    }

    fun ensureEquals(actual: Set<String>, expected: Set<String>): Boolean {
        return actual == expected
    }

    fun ensureEqualBooleans(actual: Boolean, expected: Boolean): Boolean {
        return actual == expected
    }

    fun ensureNotContains(actual: String, expected: String): Boolean {
        return actual.contains(expected)
    }

    fun ensureNull(actual: Any?): Boolean {
        return actual == null
    }

    fun <T> ensureEmpty(actual: Iterable<T>): Boolean {
        return actual.count() == 0
    }

    fun <T> ensureSingle(actual: Iterable<T>): Boolean {
        return actual.count() == 1
    }
}