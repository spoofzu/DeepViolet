#!/usr/bin/env bash
#

# -e exit on error
# -x print command prior to execution (warn: info leakage)
set -e

echo "*** before-deploy.sh, user HOME folder is $HOME"

#
# Do if: new tag
#
if [ ! -z "$TRAVIS_TAG" ]; then

	echo "*** before-deploy.sh, pre-deployment started."
	
	echo "*** gpg version info"
	gpg2 --version
	
	#echo "*** gpg-agent version info"
	#gpg-agent --version
	
	# start gpg-agent to manage passphrases
	#eval $(gpg-agent --batch --v --daemon)

	#echo "*** apply GPG tty settings"
	GPG_TTY=$(tty)
	export GPG_TTY

	# update keyrings
	openssl aes-256-cbc -a -in build/pubring.gpg.enc -out build/pubring.gpg -d -k $OPENSSL_ENCRYPT_KEY
 	openssl aes-256-cbc -a -in build/secring.gpg.enc -out build/secring.gpg -d -k $OPENSSL_ENCRYPT_KEY
 	rm ~/.gnupg/pubring.gpg
 	rm ~/.gnupg/secring.gpg
 	mv build/pubring.gpg ~/.gnupg/pubring.gpg
 	mv build/secring.gpg ~/.gnupg/secring.gpg
    sha256sum ~/.gnupg/pubring.gpg
	sha256sum ~/.gnupg/secring.gpg
	
	# Required by mvn release:prepare, fatal: empty ident name <> not allowed
	#
	git config --global user.email "noreply@travisci.com"
	git config --global user.name "DV BuildBot (via TravisCI)"

	# Print keyring for debugging
	#
	gpg2 --list-keys 
	gpg2 --list-secret-keys
	
	# Required or receives, fatal: ref HEAD is not a symbolic ref
	#
	#git checkout master
	#git pull origin master

	echo "*** before-deploy.sh, pre-deployment complete."
	
fi

