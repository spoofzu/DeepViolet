#!/usr/bin/env bash
#

# errexit: stop executing if any errors occur, by default bash will just continue past any errors to run the next command
# nounset: stop executing if an unset variable is encountered, by default bash will use an empty string for the value of such variables.
set -o errexit -o nounset

if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
	
	echo "*** deploy.sh, deploying release."
	
	#note: milton 12/2/2016, this is not optimial but keyrings are also password encrypted
	mvn --batch-mode -X release:prepare release:perform --settings="./settings.xml" -Dmaven.test.skip=true \
	     -Darguments=-Dgpg.passphrase="I love Mac." \
         -Dgpg.passphrase="I love Mac."
	     #-DconnectionUrl="scm:git:git@github.com:spoofzu/DeepViolet.git"
	
	#note: milton 12/2/2016, this is not optimial but keyrings are also password encrypted
	#mvn --batch-mode -X deploy -P sign,build-extras --settings="./settings.xml" -Dmaven.test.skip=true \
	#     -Darguments=-Dgpg.passphrase="I love Mac." \
    #     -Dgpg.passphrase="I love Mac."
         
	     # note(1): milton 12/2/2016, travis passphrase encryption does not work
		 # -Darguments=-Dgpg.passphrase="$GPG_PASSPHRASE" \
         # -Dgpg.passphrase="$GPG_PASSPHRASE"
		 
		 # note(2): milton 12/2/2016, mvn passphrase encryption does not work
		 # -Darguments=-Dgpg.passphrase="{1ytJn1Uv10gHLO/URDhNnZZgm0pIYpGSbk8h9mOPE+w=}" \
	     # -Dgpg.passphrase="{1ytJn1Uv10gHLO/URDhNnZZgm0pIYpGSbk8h9mOPE+w=}"

	echo "*** deploy.sh, deployment complete."
fi

# mvn versions:set "-DnewVersion=${tag}"
# git commit -am "${tag}"