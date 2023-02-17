#!/bin/bash

if [ ! -d "build" ]; then
  mkdir build
fi

cd build || exit 1

cmake -G Ninja .. > /dev/null
ninja > /dev/null
./mpc