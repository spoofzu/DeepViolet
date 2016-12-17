#!/usr/bin/env bash
#

# -e exit on error
# -x print command prior to execution (warn: info leakage)
set -e

echo "*** before-deploy.sh, user HOME folder is $HOME"

#echo "*** before-deploy.sh, gpg2 version info"
#gpg2 --version

# start gpg-agent to manage passphrases
#eval $(gpg-agent --batch --v --daemon)

#echo "*** gpg-agent version info"
#gpg-agent --version

#echo "*** apply GPG tty settings"
#GPG_TTY=$(tty)
#export GPG_TTY

# Don't run unless merging to "master".  Anything tagged by Maven release will not run.
if ([ "$TRAVIS_BRANCH" == "master" ] || [ ! -z "$TRAVIS_TAG" ]) && \
      [ "$TRAVIS_PULL_REQUEST" == "false" ]; then

	echo "*** before-deploy.sh, pre-deployment started."

	# update keyrings
	openssl aes-256-cbc -a -in build/pubring.gpg.enc -out build/pubring.gpg -d -k $OPENSSL_ENCRYPT_KEY
 	openssl aes-256-cbc -a -in build/secring.gpg.enc -out build/secring.gpg -d -k $OPENSSL_ENCRYPT_KEY
 	rm ~/.gnupg/pubring.gpg
 	rm ~/.gnupg/secring.gpg
 	mv build/pubring.gpg ~/.gnupg/pubring.gpg
 	mv build/secring.gpg ~/.gnupg/secring.gpg
    sha256sum ~/.gnupg/pubring.gpg
	sha256sum ~/.gnupg/secring.gpg

	# update ssh deploy keys. Required for mvn to push to github for release
    #openssl aes-256-cbc -a -in build/id_rsa.gpg.enc -out build/id_rsa.gpg -d -k $OPENSSL_ENCRYPT_KEY	
	#chmod 600 build/id_rsa.gpg
	#eval 'ssh-agent -s'
	#ssh-add build/id_rsa.gpg
	
	# Setup GH credentials for TravisCI push to GitHub (tagging)
	# Clone repo can be done via default git credentials but push
	# takes GH API key credentials.
	#
	#mkdir -p ~/.git/
    #git config credential.helper "store --file=~/.git/credentials"
    #echo "https://${GH_TOKEN}@github.com" > ~/.git/credentials
	#git remote set-url origin https://${GH_TOKEN}@github.com/spoofzu/DeepViolet.git
	
	# Required by mvn release:prepare, fatal: empty ident name <> not allowed
	#
	#git init
	git config --global user.email "noreply@travisci.com"
	git config --global user.name "DV BuildBot (via TravisCI)"
	
	# Required or receives, fatal: ref HEAD is not a symbolic ref
	#
	git checkout master
	git pull origin master

    # Maven encrypt master password
	#
	# echo "<settingsSecurity><master>{YbaXibPTjI8HEmz/lr/0WuqGHG7TU+/dJ+ZRWXf8/ek=}</master></settingsSecurity>" > ~/.m2/settings-security.xml
	echo "*** before-deploy.sh, pre-deployment complete."
	
fi

gpg --list-keys 
gpg --list-secret-keys