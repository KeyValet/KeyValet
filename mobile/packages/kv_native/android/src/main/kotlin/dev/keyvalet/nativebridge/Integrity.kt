package dev.keyvalet.nativebridge

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest

/** Native challenge-bound adapter. Self-hosted relays may omit integrity enforcement. */
object Integrity {
    fun attest(context: Context, cloudProject: Long, nonce: String, completion: (String?, Exception?) -> Unit) {
        require(cloudProject > 0 && nonce.length in 16..500)
        IntegrityManagerFactory.create(context).requestIntegrityToken(IntegrityTokenRequest.builder().setCloudProjectNumber(cloudProject).setNonce(nonce).build())
            .addOnSuccessListener { completion(it.token(), null) }.addOnFailureListener { completion(null, it) }
    }
}
