#!/usr/bin/env bash
#

set -e

if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
	echo "Publishing Maven snapshot..."
	mvn clean deploy -P sign,build-extras --settings="./settings.xml" -Dmaven.test.skip=true \
		-Darguments=-Dgpg.passphrase=$GPG_PASSPHRASE -Dgpg.passphrase=$GPG_PASSPHRASE \
		-Dgpg.Arguments="--default-key 66EF37E5 --clearsign"
    echo "Maven snapshot published..."
fi

#mvn versions:set "-DnewVersion=${tag}"
#git commit -am "${tag}"