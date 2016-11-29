#!/usr/bin/env bash
#
if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
	openssl aes-256-cbc -K $GPG_KEY_NAME -iv $GPG_PASSPHRASE -in build/signingkey.asc.enc -out build/signingkey.asc -d
	gpg --fast-import build/signingkey.asc
fi
