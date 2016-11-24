#!/usr/bin/env bash
#

if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
mvn deploy -Dgpg.defaultKeyring=false -Dgpg-keyname=56D2CBF1 -Dgpg.passphrase=${KEYRING_PASSPHRASE} -Dgpg.publicKeyring=~/build/pubring.gpg -Dgpg.secretKeyring=~/build/secring.gpg --settings ~/settings.xml
fi
