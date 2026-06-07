#include "pq_pubkey.h"

#include <oqs/sig_ml_dsa.h>
#include <oqs/oqs.h>

// RGM/Bitcoin hash functions (already in the codebase)
#include "crypto/sha256.h"
#include "crypto/ripemd160.h"

#include <cstring>

bool CPQPubKey::Verify(const std::vector<uint8_t>& hash,
                       const std::vector<uint8_t>& sig) const
{
    if (!IsValid()) return false;
    if (sig.empty()) return false;

    OQS_SIG* oqs = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (!oqs) return false;

    OQS_STATUS rc = OQS_SIG_verify(
        oqs,
        hash.data(), hash.size(),
        sig.data(),  sig.size(),
        pubkeydata.data()
    );
    OQS_SIG_free(oqs);

    return (rc == OQS_SUCCESS);
}

std::vector<uint8_t> CPQPubKey::GetHash160() const
{
    if (!IsValid()) return {};

    // SHA256 of pubkey
    uint8_t sha256out[CSHA256::OUTPUT_SIZE];
    CSHA256()
        .Write(pubkeydata.data(), pubkeydata.size())
        .Finalize(sha256out);

    // RIPEMD160 of SHA256
    uint8_t hash160out[CRIPEMD160::OUTPUT_SIZE];
    CRIPEMD160()
        .Write(sha256out, sizeof(sha256out))
        .Finalize(hash160out);

    return std::vector<uint8_t>(hash160out, hash160out + CRIPEMD160::OUTPUT_SIZE);
}
