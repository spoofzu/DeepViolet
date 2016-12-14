#!/usr/bin/env bash
#

set -e

echo "*** User HOME folder is $HOME"

echo "*** gpg2 version info"
gpg2 --version

# start gpg-agent to manage passphrases
#eval $(gpg-agent --batch --v --daemon)

#echo "*** gpg-agent version info"
#gpg-agent --version

#echo "*** apply GPG tty settings"
#GPG_TTY=$(tty)
#export GPG_TTY

if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then

	openssl aes-256-cbc -a -in build/pubring.gpg.enc -out build/pubring.gpg -d -k $OPENSSL_ENCRYPT_KEY
 	openssl aes-256-cbc -a -in build/secring.gpg.enc -out build/secring.gpg -d -k $OPENSSL_ENCRYPT_KEY
 	rm ~/.gnupg/pubring.gpg
 	rm ~/.gnupg/secring.gpg
 	mv build/pubring.gpg ~/.gnupg/pubring.gpg
 	mv build/secring.gpg ~/.gnupg/secring.gpg
    sha256sum ~/.gnupg/pubring.gpg
	sha256sum ~/.gnupg/secring.gpg

    # Maven master password
	# echo "<settingsSecurity><master>{YbaXibPTjI8HEmz/lr/0WuqGHG7TU+/dJ+ZRWXf8/ek=}</master></settingsSecurity>" > ~/.m2/settings-security.xml
	
fi

gpg2 --list-keys 
gpg2 --list-secret-keys