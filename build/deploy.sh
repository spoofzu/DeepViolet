#!/usr/bin/env bash
#

if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
	mvn deploy -P sign,build-extras --settings settings.xml
	echo $GPG_PASSPHRASE | gpg -ab --passphrase-fd 0 pom.xml 
fi
