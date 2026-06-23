#!/usr/bin/env bash
#
# Scripted demo of MY_PGP, meant to be recorded into a GIF/SVG/screenshot.
# Each command is printed (with a prompt) then executed, with small pauses
# so the recording is readable.
#
# Usage: ./screenshots/demo.sh

cd "$(dirname "$0")/.."
[ -x ./my_pgp ] || make >/dev/null 2>&1

BLUE='\033[1;34m'; GREEN='\033[1;32m'; DIM='\033[2m'; RST='\033[0m'

run() {
    printf "${BLUE}\$ ${GREEN}%s${RST}\n" "$1"
    sleep 0.6
    eval "$1"
    echo
    sleep 1.2
}

clear
printf "${DIM}# MY_PGP — A Song of Ciphers and Primes${RST}\n\n"
sleep 1

printf "${DIM}# 1. RSA: generate a key pair from two primes${RST}\n"
run "./my_pgp rsa -g d3 e3"

printf "${DIM}# 2. RSA: cipher then decipher a message${RST}\n"
run "echo 'WF' | ./my_pgp rsa -c 0101-19bb"
run "echo '8f84' | ./my_pgp rsa -d 9d5b-19bb"

printf "${DIM}# 3. AES-128: cipher a block${RST}\n"
run "echo 'All men must die' | ./my_pgp aes -c -b 57696e74657266656c6c206973206364"

printf "${DIM}# 4. PGP (RSA + AES): full hybrid encryption${RST}\n"
run "echo 'Winter is coming' | ./my_pgp pgp-aes -c '000102030405060708090a0b0c0d0e0f:010001-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3'"

printf "${DIM}# Done.${RST}\n"
sleep 1
