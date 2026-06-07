// Copyright (c) 2017 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Bech32 is a string encoding format used in newer address types.
// The output consists of a human-readable part (HRP), a separator ('1'),
// and a base32-encoded part with a 6-character checksum.
// See BIP173 for specification.

#ifndef RGM_BECH32_H
#define RGM_BECH32_H

#include <stdint.h>
#include <string>
#include <vector>

namespace bech32
{

/** Encode a Bech32 string. Returns the empty string in case of failure.
 *  hrp    : the human-readable part
 *  values : base-32 encoded data values (5-bit groups)
 */
std::string Encode(const std::string& hrp, const std::vector<uint8_t>& values);

/** Decode a Bech32 string.
 *  Returns (hrp, data) where data is the decoded base-32 values.
 *  Returns ("", {}) in case of failure.
 */
std::pair<std::string, std::vector<uint8_t>> Decode(const std::string& str);

} // namespace bech32

/** Convert from one power-of-2 number base to another.
 *
 *  If padding is true, any unaligned output bits are padded with zeros
 *  (used for encoding); if padding is false, any unaligned bits must
 *  be zero (used for decoding).
 *
 *  Returns true on success, false on failure.
 *
 *  frombits and tobits must be in [1,8].
 */
template<int frombits, int tobits, bool pad>
bool ConvertBits(std::vector<uint8_t>& out, const uint8_t* it, const uint8_t* end) {
    int val = 0;
    int bits = 0;
    const int maxv = (1 << tobits) - 1;
    while (it != end) {
        val = (val << frombits) | (*it);
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            out.push_back((val >> bits) & maxv);
        }
        ++it;
    }
    if (pad) {
        if (bits) {
            out.push_back((val << (tobits - bits)) & maxv);
        }
    } else if (bits >= frombits || ((val << (tobits - bits)) & maxv)) {
        return false;
    }
    return true;
}

#endif // BITCOIN_BECH32_H
