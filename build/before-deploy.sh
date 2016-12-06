#!/usr/bin/env bash
#

set -e

echo "User HOME folder is $HOME"
gpg2 --version

if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then

	openssl aes-256-cbc -a -in build/private-key.gpg.enc -out build/private-key.gpg -d -pass pass:$OPENSSL_ENCRYPT_KEY
	gpg2 -v --batch --import build/private-key.gpg
	
fi

gpg2 --list-keys 
gpg2 --list-secret-keys