#include <stdio.h>
#include "jni.h"
#include "xbee.h"

JNIEXPORT void JNICALL Java_uk_co_attie_libxbee_print(JNIEnv *env, jobject obj) {
	printf("Hello from libxbee!\n");
	return;
}
