#ifndef RGM_PQ_PQ_KEY_H
#define RGM_PQ_PQ_KEY_H

#include <vector>
#include <cstdint>
#include <stdexcept>

// ML-DSA-44 sizes (NIST FIPS 204)
static const size_t MLDSA44_PRIVKEY_SIZE = 2560;
static const size_t MLDSA44_PUBKEY_SIZE  = 1312;
static const size_t MLDSA44_SIG_SIZE     = 2420;

class CPQPubKey;

/**
 * CPQKey — ML-DSA-44 private key
 * Holds the raw private key bytes.
 * Call MakeNewKey() to generate a keypair.
 */
class CPQKey
{
private:
    std::vector<uint8_t> keydata;   // raw ML-DSA-44 private key (2560 bytes)
    bool fValid;

public:
    CPQKey() : fValid(false) {}
    ~CPQKey() { Clear(); }

    // Disable copy to avoid accidental key duplication
    CPQKey(const CPQKey&) = delete;
    CPQKey& operator=(const CPQKey&) = delete;

    // Move is OK
    CPQKey(CPQKey&& other) noexcept
        : keydata(std::move(other.keydata)), fValid(other.fValid)
    { other.fValid = false; }

    bool IsValid() const { return fValid && keydata.size() == MLDSA44_PRIVKEY_SIZE; }

    /**
     * Generate a new ML-DSA-44 keypair.
     * Fills this object with the private key.
     * Returns the corresponding public key via out_pubkey.
     * Returns false on failure.
     */
    bool MakeNewKey(CPQPubKey& out_pubkey);

    /**
     * Sign a 32-byte hash (sighash of transaction).
     * Returns the signature bytes (2420 bytes for ML-DSA-44).
     * Returns empty vector on failure.
     */
    std::vector<uint8_t> Sign(const std::vector<uint8_t>& hash) const;

    /**
     * Load private key from raw bytes (e.g. from wallet.dat).
     * Returns false if size is wrong.
     */
    bool SetRaw(const std::vector<uint8_t>& data);

    /**
     * Get raw private key bytes for storage in wallet.dat.
     */
    const std::vector<uint8_t>& GetRaw() const { return keydata; }

    void Clear()
    {
        if (!keydata.empty()) {
            // Zero out key material before freeing
            std::fill(keydata.begin(), keydata.end(), 0);
            keydata.clear();
        }
        fValid = false;
    }
};

#endif // BITCOIN_PQ_PQ_KEY_H
