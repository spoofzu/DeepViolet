#!/usr/bin/env bash
#
if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
	openssl aes-256-cbc -a -in build/signingkey.asc.enc -out build/signingkey.asc -d -k $OPENSSL_ENCRYPT_KEY
	gpg --fast-import build/signingkey.asc
fi
