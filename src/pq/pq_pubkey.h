#ifndef RGM_PQ_PQ_PUBKEY_H
#define RGM_PQ_PQ_PUBKEY_H

#include <vector>
#include <cstdint>
#include <array>
#include <cstddef>

static const size_t MLDSA44_PUBKEY_SIZE_CHECK = 1312;

/**
 * CPQPubKey — ML-DSA-44 public key (1312 bytes)
 * Used for:
 *   - address derivation: HASH160(pubkey) -> 20 bytes -> bech32m address
 *   - signature verification in consensus (interpreter.cpp)
 *   - storage in witness stack
 */
class CPQPubKey
{
private:
    std::vector<uint8_t> pubkeydata;

public:
    CPQPubKey() {}
    explicit CPQPubKey(const std::vector<uint8_t>& data) : pubkeydata(data) {}

    bool IsValid() const
    {
        return pubkeydata.size() == MLDSA44_PUBKEY_SIZE_CHECK;
    }

    const std::vector<uint8_t>& GetRaw() const { return pubkeydata; }

    void SetRaw(const std::vector<uint8_t>& data) { pubkeydata = data; }

    /**
     * Compute HASH160 (RIPEMD160(SHA256(pubkey))) of this public key.
     * Used to build the scriptPubKey and derive the address.
     * Returns 20-byte hash.
     */
    std::vector<uint8_t> GetHash160() const;

    /**
     * Verify an ML-DSA-44 signature against a hash.
     * hash: 32-byte sighash of the transaction
     * sig:  2420-byte ML-DSA-44 signature
     * Returns true if valid.
     */
    bool Verify(const std::vector<uint8_t>& hash,
                const std::vector<uint8_t>& sig) const;

    bool operator==(const CPQPubKey& other) const
    {
        return pubkeydata == other.pubkeydata;
    }

    bool operator!=(const CPQPubKey& other) const
    {
        return !(*this == other);
    }
};

#endif // BITCOIN_PQ_PQ_PUBKEY_H
