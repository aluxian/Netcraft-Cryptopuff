#!/bin/bash -e
for cmd in `dirname $0`/cmd/*; do
    pushd $cmd >/dev/null
    vgo install
    popd >/dev/null
done
