<div align="center">
  <h1>RGM Core</h1>
  <h3>Post-Quantum Cryptocurrency</h3>
  <p>
    <strong>ML-DSA-44 (NIST FIPS 204) · Witness Version 2 · AuxPoW Merge Mining</strong>
  </p>
  <p>
    <img src="https://img.shields.io/badge/version-2.0.0-gold" alt="version">
    <img src="https://img.shields.io/badge/algorithm-ML--DSA--44-blue" alt="algorithm">
    <img src="https://img.shields.io/badge/standard-NIST%20FIPS%20204-green" alt="standard">
    <img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="license">
  </p>
</div>

---

## What is RGM?

RGM is the first cryptocurrency with **native post-quantum digital signatures** at the consensus layer. While Bitcoin and Ethereum rely on ECDSA — vulnerable to Shor's algorithm on a quantum computer — RGM uses **ML-DSA-44**, the lattice-based signature algorithm standardized by NIST as **FIPS 204** in August 2024.

> *"Security is not a feature you add later. It is the foundation you build on."*

## Key Features

- **Post-Quantum Signatures** — ML-DSA-44 (CRYSTALS-Dilithium), NIST FIPS 204
- **Native Protocol Integration** — PQ at consensus layer, not a layer-2 solution
- **New Address Type** — `rgm1z…` (witness version 2, bech32)
- **Backward Compatible** — legacy `R…` and SegWit `rgm1q…` addresses still work
- **Merge Mining** — AuxPoW with Litecoin and Dogecoin (activates at block 200,000)
- **Proven Codebase** — fork of Dogecoin 1.14.x with liboqs 0.15.0 integration

## Algorithm Specifications

| Parameter | Value |
|-----------|-------|
| Algorithm | ML-DSA-44 (CRYSTALS-Dilithium) |
| Standard | NIST FIPS 204 (August 2024) |
| Security Level | Level 2 (~128-bit post-quantum) |
| Signature Size | 2,420 bytes |
| Public Key Size | 1,312 bytes |
| Address Format | `rgm1z…` (witness v2, bech32) |

## Network Parameters

| Parameter | Value |
|-----------|-------|
| Block Time | ~1 minute |
| Initial Reward | 50 RGM |
| SegWit + PQ Activation | Block 50,000 |
| AuxPoW Activation | Block 500,000 |
| First Halving | Block 2,102,400 → 25 RGM |

## Building

### Dependencies

- liboqs 0.15.0 (Open Quantum Safe)
- Qt 5.x (for wallet GUI)
- Berkeley DB 4.8+
- OpenSSL

### Linux

```bash
./autogen.sh
./configure \
  --with-gui \
  --with-incompatible-bdb \
  LIBOQS_CFLAGS="-I/usr/local/include" \
  LIBOQS_LIBS="-L/usr/local/lib -loqs -lssl -lcrypto"
make -j$(nproc)
```

## Usage

```bash
# Start daemon
rgmd -daemon

# Generate a post-quantum address
rgm-cli getnewaddress "" pq
# Returns: rgm1z...

# Send to PQ address
rgm-cli sendtoaddress "rgm1z..." 10.0
```

## References

- [NIST FIPS 204 — ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [Open Quantum Safe — liboqs](https://openquantumsafe.org)
- [RGM Website](https://rgmchain.net)

## License

MIT License. See [COPYING](COPYING) for details.

Based on Dogecoin Core 1.14.x © 2013-2022 The Dogecoin Core developers  
Based on Bitcoin Core © 2009-2022 The Bitcoin Core developers
