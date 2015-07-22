#!/usr/bin/env bash
set -e

ARCH_TYPE=$(uname -m)
OS_TYPE=$(uname -s)

if [ $ARCH_TYPE == "x86_64" ]; then
    GOARCH="amd64"
elif [ $ARCH_TYPE == "x86" ]; then
    GOARCH="386"
else
    echo "Unkown architecture"
    exit 1
fi

if [ $OS_TYPE == "Linux" ]; then
    GOOS="linux"
elif [ $OS_TYPE == "Darwin" ]; then
    GOOS="darwin"
else
    echo "Unkown OS"
    exit 1
fi

echo "GOARCH: $GOARCH"
echo "GOOS: $GOOS"

if [ ! -d libquic ]; then
    #git clone https://github.com/devsisters/libquic.git
    git clone git@github.com:devsisters/libquic.git
    #cd libquic
    #git checkout $REV
fi

cd libquic
rm -fr build
mkdir -p build
cd build
cmake -GNinja ..
ninja

cd ../..

TARGET_DIR=lib/${GOOS}_${GOARCH}/
mkdir -p $TARGET_DIR
cp libquic/build/boringssl/crypto/libcrypto.a libquic/build/boringssl/ssl/libssl.a libquic/build/libquic.a libquic/build/protobuf/libprotobuf.a $TARGET_DIR

rm -fr build libgoquic.a

make -j
mv libgoquic.a $TARGET_DIR

echo $TARGET_DIR updated
