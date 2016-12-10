#!/usr/bin/env bash
#

set -e

if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
	echo "Publishing Maven snapshot..."
	mvn clean deploy -P sign,build-extras --settings="settings.xml" -Dmaven.test.skip=true
    echo "Maven snapshot published..."
fi

#mvn versions:set "-DnewVersion=${tag}"
#git commit -am "${tag}"