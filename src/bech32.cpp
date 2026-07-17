// Copyright (c) 2017 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bech32.h"

namespace
{

typedef std::vector<uint8_t> data;

/** The Bech32 character set for encoding */
const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/** The Bech32 character set for decoding */
const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

/** Concatenate two byte arrays */
data Cat(data x, const data& y)
{
    x.insert(x.end(), y.begin(), y.end());
    return x;
}

/** This function will compute what 6 5-bit values to XOR into the last 6 input values,
 *  in order to make the checksum 0. These 6 values are packed together in a single 30-bit
 *  integer. The higher bits correspond to earlier values.
 *
 *  The input is interpreted as a list of coefficients of a polynomial over F = GF(32),
 *  with an implicit 1 in front. If the input is [v0,v1,v2,v3,v4], that is interpreted as
 *  the polynomial v0*x^4 + v1*x^3 + v2*x^2 + v3*x + v4. The implicit 1 is used for the
 *  constant term. The output is [o0,o1,o2,o3,o4,o5], representing the 6-term checksum:
 *  o0*x^5 + o1*x^4 + o2*x^3 + o3*x^2 + o4*x + o5.
 *
 *  The checksum is 0 if and only if the input is divisible by the polynomial
 *  x^6 + x^5 + x^4 + x^3 + x^2 + x + 1, which is the polynomial used in BIP173.
 */
uint32_t PolyMod(const data& v)
{
    uint32_t c = 1;
    for (uint8_t d : v) {
        uint8_t c0 = c >> 25;
        c = ((c & 0x1ffffff) << 5) ^ d;
        if (c0 & 1)  c ^= 0x3b6a57b2;
        if (c0 & 2)  c ^= 0x26508e6d;
        if (c0 & 4)  c ^= 0x1ea119fa;
        if (c0 & 8)  c ^= 0x3d4233dd;
        if (c0 & 16) c ^= 0x2a1462b3;
    }
    return c;
}

/** Convert to lower case. */
inline unsigned char LowerCase(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? (c - 'A') + 'a' : c;
}

/** Expand the HRP into values for checksum computation. */
data HRPExpand(const std::string& hrp)
{
    data ret;
    ret.reserve(hrp.size() + 90);
    ret.resize(hrp.size() * 2 + 1);
    for (size_t i = 0; i < hrp.size(); ++i) {
        unsigned char c = hrp[i];
        ret[i] = c >> 5;
        ret[i + hrp.size() + 1] = c & 0x1f;
    }
    ret[hrp.size()] = 0;
    return ret;
}

/** Verify a checksum. */
/** BIP-350: witness v0 uses bech32 (const 1), v1+ uses bech32m. */
uint32_t ChecksumConst(const data& values)
{
    return (!values.empty() && values[0] != 0) ? 0x2bc830a3UL : 1UL;
}

bool VerifyChecksum(const std::string& hrp, const data& values)
{
    return PolyMod(Cat(HRPExpand(hrp), values)) == ChecksumConst(values);
}

/** Create a checksum. */
data CreateChecksum(const std::string& hrp, const data& values)
{
    data enc = Cat(HRPExpand(hrp), values);
    enc.resize(enc.size() + 6);
    uint32_t mod = PolyMod(enc) ^ ChecksumConst(values);
    data ret(6);
    for (size_t i = 0; i < 6; ++i) {
        ret[i] = (mod >> (5 * (5 - i))) & 31;
    }
    return ret;
}

} // namespace

namespace bech32
{

/** Encode a Bech32 string. */
std::string Encode(const std::string& hrp, const data& values) {
    data checksum = CreateChecksum(hrp, values);
    data combined = Cat(values, checksum);
    std::string ret = hrp + '1';
    ret.reserve(ret.size() + combined.size());
    for (uint8_t c : combined) {
        ret += CHARSET[c];
    }
    return ret;
}

/** Decode a Bech32 string. */
std::pair<std::string, data> Decode(const std::string& str) {
    bool lower = false, upper = false;
    bool ok = true;
    for (size_t i = 0; ok && i < str.size(); ++i) {
        unsigned char c = str[i];
        if (c < 33 || c > 126) ok = false;
        if (c >= 'a' && c <= 'z') lower = true;
        if (c >= 'A' && c <= 'Z') upper = true;
    }
    if (lower && upper) ok = false;
    size_t pos = str.rfind('1');
    if (ok && str.size() <= 90 && pos != str.npos && pos >= 1 && pos + 7 <= str.size()) {
        data values(str.size() - 1 - pos);
        bool valid = true;
        for (size_t i = 0; i < str.size() - 1 - pos; ++i) {
            unsigned char c = str[i + pos + 1];
            int8_t rev = CHARSET_REV[c < 128 ? c : 0];
            if (rev == -1) {
                valid = false;
                break;
            }
            values[i] = rev;
        }
        if (valid) {
            std::string hrp;
            for (size_t i = 0; i < pos; ++i) {
                hrp += LowerCase(str[i]);
            }
            if (VerifyChecksum(hrp, values)) {
                return {hrp, data(values.begin(), values.end() - 6)};
            }
        }
    }
    return {};
}

} // namespace bech32
