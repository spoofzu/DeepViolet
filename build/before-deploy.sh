#!/usr/bin/env bash
#
if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
		#gpg -v --batch --import build/signingkey.asc
	openssl aes-256-cbc -a -in build/pubring.gpg.enc -out build/pubring.gpg -d -k $OPENSSL_ENCRYPT_KEY
	openssl aes-256-cbc -a -in build/secring.gpg.enc -out build/secring.gpg -d -k $OPENSSL_ENCRYPT_KEY
	rm ~/.gnupg/pubring.gpg
	rm ~/.gnupg/secring.gpg
	mv build/pubring.gpg ~/.gnupg/pubring.gpg
	mv build/secring.gpg ~/.gnupg/secring.gpg
fi

echo "HOME folder is $HOME"
gpg2 --version
gpg2 --list-keys 
gpg2 --list-secret-keys