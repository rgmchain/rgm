#include "pq_key.h"
#include "pq_pubkey.h"

// liboqs C API
#include <oqs/sig_ml_dsa.h>
#include <oqs/oqs.h>

#include <cstring>
#include <cassert>

// RGM: initialise liboqs once per process
static const bool _oqs_initialized = []() {
    OQS_init();
    return true;
}();


bool CPQKey::MakeNewKey(CPQPubKey& out_pubkey)
{
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (!sig) return false;

    std::vector<uint8_t> pub(sig->length_public_key);
    CPQKeyData priv(sig->length_secret_key);

    OQS_STATUS rc = OQS_SIG_keypair(sig, pub.data(), priv.data());
    OQS_SIG_free(sig);

    if (rc != OQS_SUCCESS) return false;

    keydata = std::move(priv);
    fValid  = true;
    out_pubkey.SetRaw(pub);
    return true;
}

std::vector<uint8_t> CPQKey::Sign(const std::vector<uint8_t>& hash) const
{
    if (!IsValid()) return {};
    if (hash.size() != 32) return {};

    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (!sig) return {};

    std::vector<uint8_t> signature(sig->length_signature);
    size_t sig_len = sig->length_signature;

    OQS_STATUS rc = OQS_SIG_sign(
        sig,
        signature.data(), &sig_len,
        hash.data(), hash.size(),
        keydata.data()
    );
    OQS_SIG_free(sig);

    if (rc != OQS_SUCCESS) return {};
    signature.resize(sig_len);
    return signature;
}

bool CPQKey::SetRaw(const std::vector<uint8_t>& data)
{
    if (data.size() != MLDSA44_PRIVKEY_SIZE) return false;
    keydata.assign(data.begin(), data.end());
    fValid  = true;
    return true;
}
