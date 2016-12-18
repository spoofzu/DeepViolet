#!/usr/bin/env bash
#

# -e exit on error
# -x print command prior to execution (warn: info leakage)
set -e

# note: milton 12/17/2016, Very important, reserved bash shell characters must be escaped
#                          with a slash.

# Exit on any github tag that is a release.
if  [[ "$TRAVIS_TAG" =~ "^v.*$"  ]]; then
	echo "*** deploy.sh, release detected, skipping deploy/release."
	exit 0;
fi

# Don't release unless merging pull request to "master".
if [ "$TRAVIS_BRANCH" == "master" ] && [ "$TRAVIS_PULL_REQUEST" == "false" ]; then
	
	echo "*** deploy.sh, deploying release."
	
	mvn release:prepare release:perform --settings="settings.xml" \
		 -Dmaven.test.skip=true \
	     -Darguments=-Dgpg.passphrase="I\ love\ Mac." \
	     -B
		 #-DdryRun=true \
	     #-DconnectionUrl="scm:git:https://${GH_TOKEN}@github.com/spoofzu/DeepViolet.git"

	echo "*** deploy.sh, deployment complete."
fi
