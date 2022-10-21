package com.babbel.mobile.android.commons.okhttpawssigner

import com.babbel.mobile.android.commons.okhttpawssigner.internal.SigningArgs
import com.babbel.mobile.android.commons.okhttpawssigner.internal.signed
import okhttp3.Request

// used in the private constructor to avoid JVM conflicts
internal data class OkHttpAwsV4SignerInternalConstructorArgs(
    val region: String?,
    val service: String?
)

/**
 * Signer for okhttp that signs the requests with the AWS V4 algorithm
 *
 * More details [here](https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html)
 */
class OkHttpAwsV4Signer private constructor(
    private val constructorArgs: OkHttpAwsV4SignerInternalConstructorArgs
) {

    constructor(region: String, service: String) : this(OkHttpAwsV4SignerInternalConstructorArgs(
        region = region,
        service = service
    ))

    constructor() : this(OkHttpAwsV4SignerInternalConstructorArgs(service = null, region = null))

    /**
     * Sign the given request with the given credentials.
     *
     * When one of the credentials is null, then no signature is produced
     */
    fun sign(
        request: Request,
        accessKeyId: String?,
        accessKey: String?
    ): Request =
        if (accessKey == null || accessKeyId == null)
            request
        else
            request.signed(
                SigningArgs(
                    accessKeyId = accessKeyId,
                    accessKey = accessKey,
                    region = constructorArgs.region,
                    service = constructorArgs.service
                )
            )
}
