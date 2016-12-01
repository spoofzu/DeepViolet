#!/usr/bin/env bash
#

set -e -u

if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
	echo "Publishing Maven snapshot..."
	mvn deploy -P sign,build-extras --settings="settings.xml" -DskipTests=true
    echo "Maven snapshot published..."
fi
