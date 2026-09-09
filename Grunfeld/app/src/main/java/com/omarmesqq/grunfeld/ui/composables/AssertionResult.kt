package com.omarmesqq.grunfeld.ui.composables

import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.omarmesqq.grunfeld.utils.TestRunner

@Composable
fun AssertionResult(testTitle: String, actual: String, expected: String) {
    val passed = TestRunner.ensureEquals(actual, expected)

    Text(
        text = if (passed) {
            "$testTitle: $actual"
        } else  {
            "$testTitle test FAIL: \"$actual\" != \"$expected\""
        },
        color = if (passed) {
            Color.Green
        } else {
            Color.Red
        }
    )
}

@Composable
fun AssertionResult(testTitle: String, actual: Long, expected: String) {
    val passed = TestRunner.ensureEquals(actual.toString(), expected)

    Text(
        text = if (passed) {
            "$testTitle: $actual"
        } else  {
            "$testTitle test FAIL: \"$actual\" != \"$expected\""
        },
        color = if (passed) {
            Color.Green
        } else {
            Color.Red
        }
    )
}

@Composable
fun AssertionResult(testTitle: String, actual: Int, expected: String) {
    val passed = TestRunner.ensureEquals(actual.toString(), expected)

    Text(
        text = if (passed) {
            "$testTitle: $actual"
        } else  {
            "$testTitle test FAIL: \"$actual\" != \"$expected\""
        },
        color = if (passed) {
            Color.Green
        } else {
            Color.Red
        }
    )
}

@Composable
fun AssertionResultNotContains(testTitle: String, actual: String, expected: String) {
    val passed = !(TestRunner.ensureNotContains(actual, expected))

    Text(
        text = if (passed) {
            "$testTitle: $actual does not contain  \"$expected\""
        } else  {
            "$testTitle test FAIL: \"$actual\" == \"$expected\""
        },
        color = if (passed) {
            Color.Green
        } else {
            Color.Red
        }
    )
}

@Composable
fun AssertionResultNull(testTitle: String, actual: Any?) {
    val passed = TestRunner.ensureNull(actual)

    Text(
        text = if (passed) {
            "$testTitle: (null)"
        } else  {
            "$testTitle test FAIL: not null -> actually: $actual "
        },
        color = if (passed) {
            Color.Green
        } else {
            Color.Red
        }
    )
}

@Composable
fun <T> AssertionResultEmpty(testTitle: String, list: Iterable<T>) {
    val passed = TestRunner.ensureEmpty(list)

    Text(
        text = if (passed) {
            "$testTitle: (empty)"
        } else  {
            "$testTitle test FAIL: not empty"
        },
        color = if (passed) {
            Color.Green
        } else {
            Color.Red
        }
    )
}