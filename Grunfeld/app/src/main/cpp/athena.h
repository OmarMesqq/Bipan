#ifndef ATHENA_H
#define ATHENA_H

#include <jni.h>

void athenaInit(JNIEnv* env);
void requestJavaBacktrace(void);
void requestNativeBacktrace(void);

#endif
