#!/usr/bin/env bash
#
# Functional test suite for MY_PGP.
# Builds the project, then checks every cryptosystem against known vectors
# and verifies cipher/decipher round-trips and error handling.
#
# Usage: ./tests/test.sh
# Exit code: 0 if all tests pass, 1 otherwise.

set -u
cd "$(dirname "$0")/.."

BIN=./my_pgp
PASS=0
FAIL=0

green() { printf "\033[32m%s\033[0m" "$1"; }
red()   { printf "\033[31m%s\033[0m" "$1"; }

# check <name> <expected> <actual>
check() {
    local name="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "  [$(green PASS)] $name"
        PASS=$((PASS + 1))
    else
        echo "  [$(red FAIL)] $name"
        echo "        expected: '$expected'"
        echo "        actual:   '$actual'"
        FAIL=$((FAIL + 1))
    fi
}

echo "==> Building project"
make re >/dev/null 2>&1 || { echo "$(red 'Build failed')"; exit 1; }

echo "==> RSA key generation"
keys=$($BIN rsa -g d3 e3)
check "public key (d3,e3)"  "public key: 0101-19bb"  "$(echo "$keys" | sed -n '1p')"
check "private key (d3,e3)" "private key: 9d5b-19bb" "$(echo "$keys" | sed -n '2p')"

echo "==> RSA cipher / decipher"
check "cipher 'WF'"     "8f84" "$(echo 'WF'   | $BIN rsa -c 0101-19bb)"
check "decipher '8f84'" "WF"   "$(echo '8f84' | $BIN rsa -d 9d5b-19bb)"

echo "==> XOR round-trip (stream)"
XKEY="5768617420646f2077652073617920746f2074686520476f64206f662044656174"
msg="You know nothing, Jon Snow"
c=$(echo "$msg" | $BIN xor -c "$XKEY")
check "xor round-trip" "$msg" "$(echo "$c" | $BIN xor -d "$XKEY")"

echo "==> AES round-trip (block, exactly 16 bytes)"
AKEY="57696e74657266656c6c206973206364"
c=$(printf 'Sixteen bytes!!!' | $BIN aes -c -b "$AKEY")
check "aes block decipher" "Sixteen bytes!!!" "$(echo "$c" | $BIN aes -d -b "$AKEY" | tr -d '\0')"

echo "==> AES round-trip (stream, length not multiple of 16)"
msg="All men must die in the long winter"
c=$(echo "$msg" | $BIN aes -c "$AKEY")
check "aes stream decipher" "$msg" "$(echo "$c" | $BIN aes -d "$AKEY" | tr -d '\0')"

echo "==> PGP-AES round-trip (RSA + AES)"
P="4b1da73924978f2e9c1f04170e46820d648edbee12ccf4d4462af89b080c86e1"
Q="bb3ca1e126f7c8751bd81bc8daa226494efb3d128f72ed9f6cacbe96e14166cb"
keys=$($BIN rsa -g "$P" "$Q")
pub=$(echo "$keys"  | sed -n '1p' | sed 's/public key: //')
priv=$(echo "$keys" | sed -n '2p' | sed 's/private key: //')
sym="000102030405060708090a0b0c0d0e0f"
out=$(echo "Winter is coming" | $BIN pgp-aes -c "$sym:$pub")
ekey=$(echo "$out" | sed -n '1p')
cmsg=$(echo "$out" | sed -n '2p')
check "pgp-aes round-trip" "Winter is coming" \
      "$(echo "$cmsg" | $BIN pgp-aes -d "$ekey:$priv" | tr -d '\0')"

echo "==> Error handling (must exit 84, no crash)"
echo "test" | $BIN aes -c 1234 >/dev/null 2>&1
check "bad AES key -> exit 84" "84" "$?"
$BIN >/dev/null 2>&1
check "no args -> exit 84" "84" "$?"

echo
echo "Results: $(green "$PASS passed"), $([ "$FAIL" -eq 0 ] && green "$FAIL failed" || red "$FAIL failed")"
[ "$FAIL" -eq 0 ]
