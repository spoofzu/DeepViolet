#!/usr/bin/env bash
#

set -e -u

echo "HOME folder is $HOME"
gpg2 --version
gpg2 --list-keys 
gpg2 --list-secret-keys

if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
		#gpg -v --batch --import build/signingkey.asc
	openssl aes-256-cbc -pass pass:$OPENSSL_ENCRYPT_KEY -in build/private-key.gpg.enc -out build/private-key.gpg -d
	gpg2 -v --batch --import build/private-key.gpg
fi
