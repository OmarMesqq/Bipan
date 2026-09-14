package com.omarmesqq.grunfeld.ui.composables

import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.omarmesqq.grunfeld.utils.TestRunner

@Composable
fun AssertionResult(testTitle: String, actual: String, expected: String) {
    val trimmedActual = actual.trim()
    val trimmedExpected = expected.trim()

    val passed = TestRunner.ensureEqualStrings(trimmedActual, trimmedExpected)
    val prettyExpected = if (expected == "") {
        "(empty)"
    } else {
        expected
    }

    Text(
        text = if (passed) {
            "$testTitle: $prettyExpected"
        } else  {
            "$testTitle test FAIL: \"$actual\" != \"$prettyExpected\""
        },
        color = if (passed) {
            Color.Green
        } else {
            Color.Red
        }
    )
}

@Composable
fun AssertionResultNotEqualStrings(testTitle: String, actual: String, expected: String) {
    val passed = !(TestRunner.ensureEqualStrings(actual, expected))
    val prettyExpected = if (expected == "") {
        "(empty)"
    } else {
        expected
    }

    Text(
        text = if (passed) {
            "$testTitle: $actual != $prettyExpected"
        } else  {
            "$testTitle test FAIL: \"$actual\" == \"$prettyExpected\""
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
    val passed = TestRunner.ensureEqualStrings(actual.toString(), expected)

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
    val passed = TestRunner.ensureEqualStrings(actual.toString(), expected)

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
fun AssertionResult(testTitle: String, actual: Boolean, expected: Boolean) {
    val passed = TestRunner.ensureEqualBooleans(actual, expected)

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
    val passed = !(TestRunner.ensureContains(actual, expected))

    Text(
        text = if (passed) {
            "$testTitle: $actual does not contain  \"$expected\""
        } else  {
            "$testTitle test FAIL: \"$actual\" contains \"$expected\""
        },
        color = if (passed) {
            Color.Green
        } else {
            Color.Red
        }
    )
}

@Composable
fun AssertionResultContains(testTitle: String, actual: String, expected: String) {
    val passed = TestRunner.ensureContains(actual, expected)

    Text(
        text = if (passed) {
            "$testTitle: $actual contains \"$expected\""
        } else  {
            "$testTitle test FAIL: \"$actual\" does NOT contain \"$expected\""
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
fun <T> AssertionResultEmpty(testTitle: String, actual: Iterable<T>) {
    val passed = TestRunner.ensureEmpty(actual)

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

@Composable
fun <T> AssertionResultSingleSpecificValueInIterable(testTitle: String, actual: Iterable<T>, expected: String) {
    val isSingleElement = TestRunner.ensureSingle(actual)
    val isEqual = TestRunner.ensureEqualStrings(actual.first() as String, expected)
    val passed = isSingleElement and isEqual

    Text(
        text = if (passed) {
            "$testTitle: list[0] == $expected"
        } else  {
            "$testTitle test FAIL: not single-element and/or actual does not match expected ($expected)"
        },
        color = if (passed) {
            Color.Green
        } else {
            Color.Red
        }
    )
}

@Composable
fun <T> AssertionResultSomeValuesInIterable(testTitle: String, actual: Iterable<T>, expected: List<String>) {
    val actualSet = actual.toSet() as Set<String>
    val expectedSet = expected.toSet()
    val passed = TestRunner.ensureEqualSets(actualSet, expectedSet)

    Text(
        text = if (passed) {
            "$testTitle: list == $expected"
        } else  {
            "$testTitle test FAIL: some values in actual are different than of those in expected"
        },
        color = if (passed) {
            Color.Green
        } else {
            Color.Red
        }
    )
}