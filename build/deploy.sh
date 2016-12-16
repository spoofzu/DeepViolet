#!/usr/bin/env bash
#

# -e exit on error
# -x print command prior to execution (warn: info leakage)
set -e

# Don't run unless merging to "master".  Anything tagged by Maven release will not run.
if ([ "$TRAVIS_BRANCH" == "master" ] || [ ! -z "$TRAVIS_TAG" ]) && \
      [ "$TRAVIS_PULL_REQUEST" == "false" ]; then
	
	echo "*** deploy.sh, deploying release."
	
	#note: milton 12/2/2016, this is not optimial but keyrings are also password encrypted
	mvn --batch-mode -X release:prepare release:perform -P sign,build-extras --settings="./settings.xml" \
		 -Dmaven.test.skip=true \
	     -Darguments=-Dgpg.passphrase="I love Mac." \
         -Dgpg.passphrase="I love Mac." \
	     -DconnectionUrl="scm:git:https://${GH_TOKEN}@github.com/spoofzu/DeepViolet.git"

	echo "*** deploy.sh, deployment complete."
fi

# mvn versions:set "-DnewVersion=${tag}"
# git commit -am "${tag}"