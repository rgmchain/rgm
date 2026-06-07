// Copyright (c) 2011-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rgmaddressvalidator.h"

#include "base58.h"
#include "script/standard.h"

/* Base58 and bech32 characters:
   Base58: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
   Bech32: hrp + "1" separator + "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
   The entry validator is intentionally permissive (accepts the union of
   both character sets); final address validity is checked by
   BitcoinAddressCheckValidator via DecodeDestination.

  Base58 is:
  - All numbers except for '0'
  - All upper-case letters except for 'I' and 'O'
  - All lower-case letters except for 'l'
*/

BitcoinAddressEntryValidator::BitcoinAddressEntryValidator(QObject *parent) :
    QValidator(parent)
{
}

QValidator::State BitcoinAddressEntryValidator::validate(QString &input, int &pos) const
{
    Q_UNUSED(pos);

    // Empty address is "intermediate" input
    if (input.isEmpty())
        return QValidator::Intermediate;

    // Correction
    for (int idx = 0; idx < input.size();)
    {
        bool removeChar = false;
        QChar ch = input.at(idx);
        // Corrections made are very conservative on purpose, to avoid
        // users unexpectedly getting away with typos that would normally
        // be detected, and thus sending to the wrong address.
        switch(ch.unicode())
        {
        // Qt categorizes these as "Other_Format" not "Separator_Space"
        case 0x200B: // ZERO WIDTH SPACE
        case 0xFEFF: // ZERO WIDTH NO-BREAK SPACE
            removeChar = true;
            break;
        default:
            break;
        }

        // Remove whitespace
        if (ch.isSpace())
            removeChar = true;

        // To next character
        if (removeChar)
            input.remove(idx, 1);
        else
            ++idx;
    }

    // Validation
    // Accept the union of base58 and bech32 character sets so that the user
    // can type any address type (legacy R..., P2SH r..., bech32 rgm1...) without
    // the input field rejecting characters mid-entry.
    // Base58  : [1-9A-HJ-NP-Za-km-z]   (no 0, I, O, l)
    // Bech32  : [0-9a-z]  (lower-case alphanumeric; separator '1' included above)
    // Union   : [0-9A-Za-z] minus {I, O, l} — but bech32 needs '0' and 'l' is
    //           forbidden in base58 yet valid in bech32 charset; we keep 'l' and
    //           '0' here for bech32, which is safe because a final validity check
    //           is done by BitcoinAddressCheckValidator.
    QValidator::State state = QValidator::Acceptable;
    for (int idx = 0; idx < input.size(); ++idx)
    {
        int ch = input.at(idx).unicode();

        if ((ch >= '0' && ch <= '9') ||
            (ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z'))
        {
            // All alphanumeric characters accepted at entry stage.
            // The strict check (IsValid / DecodeDestination) happens in
            // BitcoinAddressCheckValidator::validate().
        }
        else
        {
            state = QValidator::Invalid;
        }
    }

    return state;
}

BitcoinAddressCheckValidator::BitcoinAddressCheckValidator(QObject *parent) :
    QValidator(parent)
{
}

QValidator::State BitcoinAddressCheckValidator::validate(QString &input, int &pos) const
{
    Q_UNUSED(pos);
    // Validate the passed RGM address — supports legacy (R...), P2SH (r...),
    // and native SegWit bech32 (rgm1.../trgm1.../rrgm1...) addresses.
    CTxDestination dest = DecodeDestination(input.toStdString());
    if (IsValidDestination(dest))
        return QValidator::Acceptable;

    return QValidator::Invalid;
}
