package com.omarmesqq.grunfeld.utils

object TestRunner {
    fun ensureEquals(actual: String, expected: String): Boolean {
//        if (actual.count { it == ',' } == 1) {
//            return expected.replace(",", "") == expected
//        }
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

    fun <T> ensureEmpty(list: Iterable<T>): Boolean {
        return list.count() == 0
    }

    fun <T> ensureSingle(list: Iterable<T>): Boolean {
        return list.count() == 1
    }
}