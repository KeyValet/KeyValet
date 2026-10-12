#include "kv_mobile.h"
#include <jni.h>
#include <cstring>

static JavaVM* vm;
static jclass runtime;
static jmethodID key_operation;
static intptr_t key_callback(uint32_t slot, uint32_t operation, const uint8_t* input, size_t size, uint8_t* output, size_t capacity) {
    if (size > 128 * 1024 || capacity > 128 * 1024 || runtime == nullptr) return -1;
    JNIEnv* env = nullptr;
    bool attached = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_EDETACHED;
    if (attached && vm->AttachCurrentThread(&env, nullptr) != JNI_OK) return -1;
    jbyteArray bytes = env->NewByteArray(static_cast<jsize>(size));
    if (bytes != nullptr && size > 0) env->SetByteArrayRegion(bytes, 0, static_cast<jsize>(size), reinterpret_cast<const jbyte*>(input));
    auto result = static_cast<jbyteArray>(env->CallStaticObjectMethod(runtime, key_operation, static_cast<jint>(slot), static_cast<jint>(operation), bytes));
    intptr_t written = -1;
    if (!env->ExceptionCheck() && result != nullptr) {
        auto count = env->GetArrayLength(result);
        if (static_cast<size_t>(count) <= capacity) {
            env->GetByteArrayRegion(result, 0, count, reinterpret_cast<jbyte*>(output)); written = count;
        }
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (result != nullptr) env->DeleteLocalRef(result);
    if (bytes != nullptr) env->DeleteLocalRef(bytes);
    if (attached) vm->DetachCurrentThread();
    return written;
}
static jstring consume(JNIEnv* env, char* value) {
    if (value == nullptr) return nullptr;
    auto bytes = env->NewByteArray(static_cast<jsize>(std::strlen(value)));
    env->SetByteArrayRegion(bytes, 0, static_cast<jsize>(std::strlen(value)), reinterpret_cast<const jbyte*>(value));
    kv_mobile_free(value);
    auto cls = env->FindClass("java/lang/String");
    auto constructor = env->GetMethodID(cls, "<init>", "([BLjava/lang/String;)V");
    auto utf8 = env->NewStringUTF("UTF-8");
    auto result = static_cast<jstring>(env->NewObject(cls, constructor, bytes, utf8));
    env->DeleteLocalRef(bytes); env->DeleteLocalRef(utf8); env->DeleteLocalRef(cls); return result;
}
extern "C" JNIEXPORT jstring JNICALL Java_dev_keyvalet_nativebridge_NativeRuntime_nativeOpen(JNIEnv* env, jclass cls, jstring config) {
    env->GetJavaVM(&vm);
    if (runtime == nullptr) { runtime = static_cast<jclass>(env->NewGlobalRef(cls)); key_operation = env->GetStaticMethodID(cls, "keyOperation", "(II[B)[B"); }
    const char* input = env->GetStringUTFChars(config, nullptr);
    auto result = consume(env, kv_mobile_open(input, key_callback));
    env->ReleaseStringUTFChars(config, input); return result;
}
extern "C" JNIEXPORT jstring JNICALL Java_dev_keyvalet_nativebridge_NativeRuntime_nativeCall(JNIEnv* env, jclass, jstring command) {
    const char* input = env->GetStringUTFChars(command, nullptr);
    auto result = consume(env, kv_mobile_call(input)); env->ReleaseStringUTFChars(command, input); return result;
}
