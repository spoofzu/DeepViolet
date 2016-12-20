#!/usr/bin/env bash
#

# -e exit on error
# -x print command prior to execution (warn: info leakage)
set -e

# note: milton 12/17/2016, Very important, reserved bash shell characters must be escaped
#                          with a slash like -Darguments=-Dgpg.passphrase="I\ love\ Mac." \
#

#
# Do if: new tag
#
if [ ! -z "$TRAVIS_TAG" ]; then
	
	echo "*** deploy.sh, deploying release."
	
	# 
	# Set version in pom.xml to $TRAVIS_TAG
	#
	mvn --settings="settings.xml" org.codehaus.mojo:versions-maven-plugin:2.3:set \
	-DnewVersion="$TRAVIS_TAG" \
	-Prelease \
	-X
	
	#
	# Create GPG keys
	#
	source build/gpg.sh
	
	# 
	# Deploy
	#			 
    mvn clean deploy --settings="settings.xml" \
	-DskipTests=true \
    --batch-mode \
	--update-snapshots \
	-Prelease \
    -Dgpg.passphrase="I\ love\ Mac." \
	-Darguments=-Dgpg.passphrase="I\ love\ Mac." \
	-X

	echo "*** deploy.sh, deployment complete."
fi
