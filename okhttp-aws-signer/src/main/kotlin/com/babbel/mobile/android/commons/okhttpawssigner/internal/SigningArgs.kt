package com.babbel.mobile.android.commons.okhttpawssigner.internal

internal data class SigningArgs(
    val accessKeyId: String,
    val accessKey: String,
    val region: String?,
    val service: String?
)
