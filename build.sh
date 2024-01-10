#! /usr/bin/bash

LIBS='-lpcap'
COMPILER_FLAGS=''
SRC_DIR='src'
BUILD_DIR='build'


echo "Building!"
rm "$BUILD_DIR"/*
gcc "$COMPILER_FLAGS" -o "$BUILD_DIR"/packet_slice "$SRC_DIR"/* "$LIBS"
cp "$SRC_DIR"/styles.css "$BUILD_DIR"
