#!/usr/bin/env bash
#

# -e exit on error
# -x print command prior to execution (warn: info leakage)
set -e

if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
	
	echo "*** deploy.sh, deploying release."
	
	#note: milton 12/2/2016, this is not optimial but keyrings are also password encrypted
	mvn --batch-mode -X clean deploy release:prepare release:perform -P sign,build-extras --settings="./settings.xml" \
		 -Dmaven.test.skip=true \
	     -Darguments=-Dgpg.passphrase="I love Mac." \
         -Dgpg.passphrase="I love Mac." \
	     -DconnectionUrl="scm:git:https://${GH_TOKEN}@github.com/spoofzu/DeepViolet.git"
	
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