#!/usr/bin/env bash
#

# errexit: stop executing if any errors occur, by default bash will just continue past any errors to run the next command
# nounset: stop executing if an unset variable is encountered, by default bash will use an empty string for the value of such variables.
set -o errexit -o nounset

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
	
	# Required by mvn release:prepare
	git config --global user.email "noreply@travisci.com"
	git config --global user.name "DeepViolet Travisci Bot"
	
	# Required or receives, fatal: ref HEAD is not a symbolic ref
	git checkout master
	git pull origin master
	
	# Setup GH credentials for TravisCI push to GitHub (tagging)
	# Clone repo can be done via default git credentials but push
	# takes GH API key credentials.
    - git config credential.helper "store --file=.git/credentials"
    - echo "https://${GH_TOKEN}:@github.com" > .git/credentials

    # Maven master password
	# echo "<settingsSecurity><master>{YbaXibPTjI8HEmz/lr/0WuqGHG7TU+/dJ+ZRWXf8/ek=}</master></settingsSecurity>" > ~/.m2/settings-security.xml
	
fi

gpg2 --list-keys 
gpg2 --list-secret-keys