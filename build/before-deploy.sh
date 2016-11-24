#!/usr/bin/env bash
#
echo "<settings><servers><server><id>ossrh</id><username>\${OSSRH_USER}</username><password>\${OSSRH_PASS}</password><filePermissions>664</filePermissions><directoryPermissions>775</directoryPermissions></server></servers></settings>" > ~/settings.xml

if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
    openssl aes-256-cbc -d -in build/pubring.gpg.enc -out build/pubring.gpg -pass pass:${ENCRYPTION_PASSWORD}
    openssl aes-256-cbc -d -in build/secring.gpg.enc -out build/secring.gpg -pass pass:${ENCRYPTION_PASSWORD}
fi
