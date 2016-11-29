#!/usr/bin/env bash
#
if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
	echo $OPENSSL_ENCRYPT_KEY | openssl aes-256-cbc -a -salt -in build/signingkey.asc.enc -out build/signingkey.asc -d 
	gpg --fast-import build/signingkey.asc
fi
