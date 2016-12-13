#!/usr/bin/env bash
#

set -e

if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
	echo "Publishing Maven snapshot..."
	git config --global user.email "milton.smith.rr+travisci@gmail.com"
	git config --global user.name "travisci"
	mvn --batch-mode -X deploy -P sign,build-extras --settings="./settings.xml" -Dgpg.dryRun=true -Dmaven.test.skip=true -Darguments=-Dgpg.passphrase="$GPG_PASSPHRASE"
    echo "Maven snapshot published..."
fi

#mvn versions:set "-DnewVersion=${tag}"
#git commit -am "${tag}"