#!/bin/bash

git submodule init

git submodule update

if pushd MoonGen > /dev/null; then
    ./build.sh

    popd > /dev/null
fi
