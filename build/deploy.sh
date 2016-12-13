#!/usr/bin/env bash
#

set -e

if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
	echo "Publishing Maven snapshot..."
	mvn --batch-mode -X deploy --settings="./settings.xml" -Dmaven.test.skip=true -Darguments=-Dgpg.passphrase="$GPG_PASSPHRASE"
    echo "Maven snapshot published..."
fi

#mvn versions:set "-DnewVersion=${tag}"
#git commit -am "${tag}"