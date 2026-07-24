# RGM — RGMChain Core

RGMChain is a fork of **Dogecoin 1.14.x** that adds a native post-quantum address type
signed with **ML-DSA-44** (CRYSTALS-Dilithium), the algorithm standardised by NIST as
**FIPS 204** in August 2024.

Everything else — the UTXO model, Scrypt proof of work, the wallet, the RPC interface —
works the way it does in Dogecoin. The post-quantum support is an addition, not a rewrite.

**Mainnet launched 27 July 2026, 17:00 UTC. No premine, no presale, no dev fund.**

---

## Why

Bitcoin-family chains sign with ECDSA. Once an address has spent, its public key sits
on-chain permanently, and Shor's algorithm running on a sufficiently capable quantum
computer could derive the private key from it.

Whether such a machine will be built, and when, is genuinely unknown. But coins held for
years carry that uncertainty, and adding an option later is far harder than starting with
it available.

### The honest tradeoff

An ML-DSA-44 signature is **2,420 bytes**. ECDSA is 72. That is roughly 33× the witness
data, and spending a post-quantum input costs accordingly. This is inherent to
lattice-based signatures and cannot be engineered away.

So RGM does not force it. Three address types coexist:

| Type | Prefix | Use |
|---|---|---|
| Legacy | `R…` | compatibility |
| SegWit v0 | `rgm1q…` | everyday spending |
| Post-quantum | `rgm1z…` | long-term savings |

**SegWit for circulation, post-quantum for savings.** The wallet picks change output types
automatically (PQ > bech32 > legacy).

---

## Specifications

| | |
|---|---|
| Base | Dogecoin 1.14.x fork |
| Proof of work | Scrypt |
| Difficulty | LWMA (window 45) + DigiShield, from block 1 |
| Block time | 60 seconds |
| Block reward | 50 RGM |
| Halving | every 2,102,400 blocks (~4 years) |
| Coinbase maturity | 30 blocks |
| PQ algorithm | ML-DSA-44 via liboqs 0.15.0 |
| P2P / RPC port | 14030 / 14031 |
| Premine | none |

## Activation schedule

All heights are compiled in advance — no hard forks are planned.

| Height | What activates | Approx. |
|---|---|---|
| 1 | Solo mining, open to everyone | launch |
| 25,000 | Pool mining | ~17 days |
| 50,000 | SegWit + post-quantum addresses | ~35 days |
| 500,000 | AuxPoW merge-mining with LTC / DOGE | ~347 days |
| 2,102,400 | First halving → 25 RGM | ~4 years |

---

## Downloads

Prebuilt binaries are on the [Releases](https://github.com/rgmchain/rgm/releases) page.

**Verify before running.** Checksums are published in `SHA256SUMS.txt` on the release page,
on [rgmchain.net](https://rgmchain.net), and in the announcement thread — compare at least
two sources.

```bash
sha256sum -c SHA256SUMS.txt
```

---

## Running a node

Create `rgm.conf` in the data directory:

```
server=1
daemon=1
txindex=1

# There is no DNS seed yet — this line is required
addnode=185.23.80.53:14030
```

Data directory:

- Linux — `~/.rgm/`
- Windows — `%APPDATA%\RGM\`

Then:

```bash
./rgmd
./rgm-cli getblockchaininfo
```

### Mining

Blocks 1 to 25,000 are solo only. Pool mining activates automatically at 25,000.

```bash
./rgm-cli getnewaddress
./rgm-cli generate 1 2147483647
```

A GUI solo miner for Windows is available on [rgmchain.net](https://rgmchain.net).

---

## Building from source

Standard Bitcoin Core 0.14 build process, plus liboqs.

```bash
sudo apt install build-essential libtool autotools-dev automake pkg-config \
     bsdmainutils python3 libssl-dev libevent-dev libboost-all-dev \
     libdb5.3-dev libdb5.3++-dev libminiupnpc-dev libzmq3-dev

# liboqs 0.15.0 — see https://github.com/open-quantum-safe/liboqs

./autogen.sh
./configure --with-incompatible-bdb
make -j$(nproc)
```

For the Qt GUI, add `libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools
libprotobuf-dev protobuf-compiler libqrencode-dev`.

---

## Known limitations

These are real and worth knowing before you decide to participate:

- **Low hashrate at launch.** Until merge-mining activates at block 500,000, a 51% attack
  is affordable for anyone with meaningful Scrypt hashpower. Treat confirmations
  accordingly.
- **No checkpoints yet** in chainparams, and `minimumchainwork` is zero. Both will be added
  in the first update, once the chain has real work behind it.
- **One public seed node.** A DNS seed and fixed seeds are planned but not in place. If the
  seed goes down, new nodes need a manual `addnode`.
- **Post-quantum addresses activate at block 50,000**, not at launch.
- **No exchange listings.** None have been approached and there is nothing to announce.
- **No external code review.** This is a one-person project. Review is welcome and needed.

---

## Contributing

Bug reports, criticism of the design, and code review are all welcome — especially of the
post-quantum implementation. If something there is wrong, I would rather hear it now than
after people hold coins.

Open an issue, or write in Telegram.

---

## Links

- Website — https://rgmchain.net
- Block explorer — https://mainnet.rgmchain.net
- Wallet (Python / SPV) — https://github.com/rgmchain/rgmwallet
- Telegram — https://t.me/RGM_Core
- X — https://x.com/RGM_Core

## License

MIT, inherited from Bitcoin Core and Dogecoin. See [COPYING](COPYING).

Post-quantum support uses [liboqs](https://github.com/open-quantum-safe/liboqs) from the
Open Quantum Safe project.
