#!/usr/bin/env bash
#

set -e -u

echo "User HOME folder is $HOME"
gpg2 --version

if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then

	openssl aes-256-cbc -pass pass:$OPENSSL_ENCRYPT_KEY -in build/private-key.gpg.enc -out build/private-key.gpg -d
	gpg2 -v --batch --import build/private-key.gpg
	
fi

gpg2 --list-keys 
gpg2 --list-secret-keys