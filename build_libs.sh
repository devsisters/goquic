#!/bin/sh -e

while getopts "arh" opt; do
  case $opt in
    a)
      BUILD_CLEAN=1
      ;;
    r)
      if [ -z $GOQUIC_BUILD ]; then
        GOQUIC_BUILD="Release"
      else
        echo "Both GOQUIC_BUILD and -r provided. Please provide only either one."
        exit 1;
      fi
      ;;
    h)
      echo "Usage: ./build_libs.sh [-a] [-r] [-h]"
      echo "  -a: Force rebuild all"
      echo "  -r: Release build"
      echo "  -h: Help"
      exit 1;
      ;;
  esac
done

ARCH_TYPE=$(uname -m)
OS_TYPE=$(uname -s)

if [ $ARCH_TYPE = "x86_64" ]; then
    GOARCH="amd64"
elif [ $ARCH_TYPE = "x86" ]; then
    GOARCH="386"
elif [ $ARCH_TYPE = "amd64" ]; then       # freeBSD?
    GOARCH="amd64"
else
    echo "Unknown architecture"
    exit 1
fi

if [ $OS_TYPE = "Linux" ]; then
    GOOS="linux"
elif [ $OS_TYPE = "Darwin" ]; then
    GOOS="darwin"
elif [ $OS_TYPE = "FreeBSD" ]; then
    GOOS="freebsd"
else
    echo "Unknown OS"
    exit 1
fi

if [ "$GOQUIC_BUILD" = "Release" ]; then
    OPT="-DCMAKE_BUILD_TYPE=Release"
    BUILD_DIR="build/release"
else
    OPT=""
    BUILD_DIR="build/debug"
fi

echo "GOARCH: $GOARCH"
echo "GOOS: $GOOS"
echo "OPTION: $OPT"

if [ ! -d libquic ]; then
    echo "try git submodule init && git submodule update first"
    exit 1
fi

if [ ! -z $BUILD_CLEAN ]; then
  rm -fr libquic/$BUILD_DIR
fi
mkdir -p libquic/$BUILD_DIR

cd libquic/$BUILD_DIR
cmake -GNinja $OPT ../..
cd -

ninja -Clibquic/$BUILD_DIR

TARGET_DIR=lib/${GOOS}_${GOARCH}/
mkdir -p $TARGET_DIR
cp libquic/$BUILD_DIR/boringssl/crypto/libcrypto.a libquic/$BUILD_DIR/boringssl/ssl/libssl.a libquic/$BUILD_DIR/libquic.a libquic/$BUILD_DIR/protobuf/libprotobuf.a $TARGET_DIR

rm -fr build libgoquic.a

if [ $GOOS = "freebsd" ]; then
    GOQUIC_BUILD=$GOQUIC_BUILD gmake -j
else
    GOQUIC_BUILD=$GOQUIC_BUILD make -j
fi
mv libgoquic.a $TARGET_DIR

echo $TARGET_DIR updated
