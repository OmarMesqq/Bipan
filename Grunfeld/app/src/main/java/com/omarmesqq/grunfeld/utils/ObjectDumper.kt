package com.omarmesqq.grunfeld.utils

import android.util.Log
import java.lang.reflect.Array
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.util.ArrayList
import kotlin.collections.forEach
import kotlin.jvm.java


private const val TAG = "GrunfeldObjectDumper"
object ObjectDumper {
    /**
     * My attempt at runtime object dumping
     * Who would win?
     * A framework that erases types at runtime or me?
     */
    fun dumpSomeObject(obj: Any?, depth: Int = 0): String {
        val sb = StringBuilder()
        val indentLevel: (d: Int) -> String = {
            "\t".repeat(it)
        }

        if (obj == null) {
            return ""
        }

        val shortClzName = obj::class.simpleName ?: "NULL class name"

        val declaredFields = obj.javaClass.declaredFields

        declaredFields.forEach { f ->
            f.isAccessible = true

            // Heuristic for public static fields that don't matter in the dump
            val isNoise: (s: String) -> Boolean = { s ->
                val innerLambda: (c: Char) -> Boolean = { c ->
                    c.isUpperCase() || c == '_'
                }
                s.all { innerLambda(it) } || s.startsWith("RIL")
            }

            if (!isNoise(f.name)) {
                val value = f.get(obj)
                if (f.type.isPrimitive) {
                    sb.appendLine("${indentLevel(depth)}${f.name}: $value")
                }
                else if (f.type.isAssignableFrom(String::class.java)) {
                    val valueCopy = value as String
                    if (valueCopy.isNotEmpty()) {
                        sb.appendLine("${indentLevel(depth)}${f.name}: $value")
                    }
                }
                else {
                    sb.appendLine("${indentLevel(depth)}${f.name}:")
                    val depthCopy = depth + 1

                    if (isIterable(f.type)) {
                        val iterableValue = value as Iterable<*>
                        iterableValue.forEach {
                            val nestedRes = dumpSomeObject(it as Any, depthCopy)
                            if (nestedRes.isNotEmpty()) {
                                sb.appendLine("${indentLevel(depth)}$nestedRes")
                            }
                        }
                    } else if (f.type.isArray) {
                        if (value == null) {
                            return ""
                        }
                        val reflectedArrayClz = Class.forName("java.lang.reflect.Array")
                        val getLengthMethod: Method = reflectedArrayClz.getMethod("getLength", Object::class.java)
                        val getter: Method = reflectedArrayClz.getMethod("get", Object::class.java, Int::class.java)

                        val length = getLengthMethod.invoke(null, value) as Int
                        var i = 0
                        while(i < length) {
                            try {
                                val arrVal = getter.invoke(null, obj, i)
                                if (arrVal != null) {
                                    sb.appendLine("${indentLevel(depth)}${f.name}: $arrVal")
                                }
                            } catch (e: InvocationTargetException) {
                                Log.e(TAG, "${indentLevel(depth)}${f.name}: FAILED TO GET VALUE(${e.cause})")
                            } finally {
                                i += 1
                            }
                        }
                    } else {
                        val nestedRes = dumpSomeObject(value)
                        if (nestedRes.isNotEmpty()) {
                            sb.appendLine("${indentLevel(depth)}${nestedRes}")
                        }
                    }
                }
            }
        }
        return sb.toString()
    }

    private fun isIterable(clz: Class<*>): Boolean {
        if (clz.isAssignableFrom(List::class.java)) {
            return true
        } else if (clz.isAssignableFrom(Array::class.java)) {
            return true
        } else if (clz.isAssignableFrom(ArrayList::class.java)) {
            return true
        }
        else {
            Log.e(TAG, "isIterable else case:\n${clz.name} | ${clz.simpleName} | ${clz.canonicalName} | ${clz.typeName}")
            return false
        }
    }
}