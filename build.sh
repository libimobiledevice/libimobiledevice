#!/usr/bin/env bash

#brew install libtool
#brew install automake
#brew install pkgconfig
#sudo xcode-select -s /Applications/Xcode.app

function build_libimobiledevice()
{
    BASE_PATH="`pwd`"

    DEPENDENCIES_PATH=$BASE_PATH/dependencies


    LIBIMOBILEDEVICE_GLUE_PATH=$DEPENDENCIES_PATH/libimobiledevice-glue
    LIBUSBMUXD_PATH=$DEPENDENCIES_PATH/libusbmuxd
    OPENSSL_PATH=$DEPENDENCIES_PATH/OpenSSL-for-iPhone

    if [[ $1 == "ios" ]];then
        echo "ios"
        export SDKROOT="`xcrun --sdk iphoneos --show-sdk-path`"
        export CPPFLAGS="-mios-version-min=11.0 -fembed-bitcode"
        export CFLAGS="-mios-version-min=11.0 -fembed-bitcode"

        RELASE_PATH=$BASE_PATH/release_ios
        LIBPILIST_RELEASE_PATH=$RELASE_PATH/libplist
        LIBIMOBILEDEVICE_GLUE_RELEASE_PATH=$RELASE_PATH/libimobiledevice-glue
        LIBUSBMUXD_RELEASE_PATH=$RELASE_PATH/libusbmuxd
        OPENSSL_RELEASE_PATH=$RELASE_PATH/openssl
        LIBIMOBILEDEVICE_RELEASE_PATH=$RELASE_PATH/libimobiledevice
        HOST=arm64-apple-darwin
        export PKG_CONFIG_PATH=$LIBPILIST_RELEASE_PATH/lib/pkgconfig:$LIBIMOBILEDEVICE_GLUE_RELEASE_PATH/lib/pkgconfig:$LIBUSBMUXD_RELEASE_PATH/lib/pkgconfig
        export openssl_CFLAGS=-I$OPENSSL_RELEASE_PATH/include
        export openssl_LIBS="-L$OPENSSL_RELEASE_PATH/lib  -lssl -lcrypto"
    elif [[ $1 == "macosx" ]]; then
        #statements
        echo "macosx"
    elif [[ $1 == "macosx_m1" ]]; then
        echo "macosx_m1"
        RELASE_PATH=$BASE_PATH/release_macosx
        LIBPILIST_RELEASE_PATH=$RELASE_PATH/libplist
        LIBIMOBILEDEVICE_GLUE_RELEASE_PATH=$RELASE_PATH/libimobiledevice-glue
        LIBUSBMUXD_RELEASE_PATH=$RELASE_PATH/libusbmuxd
        OPENSSL_RELEASE_PATH=/usr/local/homebrew/Cellar/openssl@3/3.0.1/
        LIBIMOBILEDEVICE_RELEASE_PATH=$RELASE_PATH/libimobiledevice
        HOST=arm64-apple-darwin
        export PKG_CONFIG_PATH=$LIBPILIST_RELEASE_PATH/lib/pkgconfig:$LIBIMOBILEDEVICE_GLUE_RELEASE_PATH/lib/pkgconfig:$LIBUSBMUXD_RELEASE_PATH/lib/pkgconfig:/opt/homebrew/Cellar/openssl@3/3.0.1/lib/pkgconfig
    else
        echo "macosx_m1"
    fi

    ####libimobiledevice
    cd $BASE_PATH
    make
    make install
}

function build_target()
{

    #libplist

    BASE_PATH="`pwd`"

    DEPENDENCIES_PATH=$BASE_PATH/dependencies


    LIBIMOBILEDEVICE_GLUE_PATH=$DEPENDENCIES_PATH/libimobiledevice-glue
    LIBUSBMUXD_PATH=$DEPENDENCIES_PATH/libusbmuxd
    OPENSSL_PATH=$DEPENDENCIES_PATH/OpenSSL-for-iPhone

    if [[ $1 == "ios" ]];then
        echo "ios"
        export SDKROOT="`xcrun --sdk iphoneos --show-sdk-path`"
        export CPPFLAGS="-mios-version-min=11.0 -fembed-bitcode"
        export CFLAGS="-mios-version-min=11.0 -fembed-bitcode"

        RELASE_PATH=$BASE_PATH/release_ios
        LIBPILIST_RELEASE_PATH=$RELASE_PATH/libplist
        LIBIMOBILEDEVICE_GLUE_RELEASE_PATH=$RELASE_PATH/libimobiledevice-glue
        LIBUSBMUXD_RELEASE_PATH=$RELASE_PATH/libusbmuxd
        OPENSSL_RELEASE_PATH=$RELASE_PATH/openssl
        LIBIMOBILEDEVICE_RELEASE_PATH=$RELASE_PATH/libimobiledevice
        HOST=arm64-apple-darwin
        export PKG_CONFIG_PATH=$LIBPILIST_RELEASE_PATH/lib/pkgconfig:$LIBIMOBILEDEVICE_GLUE_RELEASE_PATH/lib/pkgconfig:$LIBUSBMUXD_RELEASE_PATH/lib/pkgconfig
        export openssl_CFLAGS=-I$OPENSSL_RELEASE_PATH/include
        export openssl_LIBS="-L$OPENSSL_RELEASE_PATH/lib  -lssl -lcrypto"
    elif [[ $1 == "macosx_x86_64" ]]; then
        echo "macosx_x86_64"

        export SDKROOT="`xcrun --sdk macosx --show-sdk-path`"
        export CPPFLAGS="-mmacosx-version-min=10.15 -fembed-bitcode"
        export CFLAGS="-mmacosx-version-min=10.15 -fembed-bitcode"

        RELASE_PATH=$BASE_PATH/release_macosx
        LIBPILIST_RELEASE_PATH=$RELASE_PATH/libplist
        LIBIMOBILEDEVICE_GLUE_RELEASE_PATH=$RELASE_PATH/libimobiledevice-glue
        LIBUSBMUXD_RELEASE_PATH=$RELASE_PATH/libusbmuxd
        OPENSSL_RELEASE_PATH=/usr/local/homebrew/Cellar/openssl@3/3.0.1/
        LIBIMOBILEDEVICE_RELEASE_PATH=$RELASE_PATH/libimobiledevice
        HOST=x86_64-apple-darwin
        export PKG_CONFIG_PATH=$LIBPILIST_RELEASE_PATH/lib/pkgconfig:$LIBIMOBILEDEVICE_GLUE_RELEASE_PATH/lib/pkgconfig:$LIBUSBMUXD_RELEASE_PATH/lib/pkgconfig:/usr/local/Cellar/openssl@3/3.0.1/lib/pkgconfig
    elif [[ $1 == "macosx_arm64" ]]; then
        echo "macosx_arm64"
        RELASE_PATH=$BASE_PATH/release_macosx
        LIBPILIST_RELEASE_PATH=$RELASE_PATH/libplist
        LIBIMOBILEDEVICE_GLUE_RELEASE_PATH=$RELASE_PATH/libimobiledevice-glue
        LIBUSBMUXD_RELEASE_PATH=$RELASE_PATH/libusbmuxd
        OPENSSL_RELEASE_PATH=/usr/local/homebrew/Cellar/openssl@3/3.0.1/
        LIBIMOBILEDEVICE_RELEASE_PATH=$RELASE_PATH/libimobiledevice
        HOST=arm64-apple-darwin
        export PKG_CONFIG_PATH=$LIBPILIST_RELEASE_PATH/lib/pkgconfig:$LIBIMOBILEDEVICE_GLUE_RELEASE_PATH/lib/pkgconfig:$LIBUSBMUXD_RELEASE_PATH/lib/pkgconfig:/opt/homebrew/Cellar/openssl@3/3.0.1/lib/pkgconfig
    else
        echo "macosx_arm64"
    fi

    

    if [ ! -d "dependencies" ];then
        mkdir dependencies
    fi

    ####libplist

    cd $DEPENDENCIES_PATH
    if [ -d "libplist" ]
    then
        cd libplist
        git pull
        git submodule init
        git submodule update
    else
        git clone https://github.com/libimobiledevice/libplist.git
        cd libplist
        git submodule init
        git submodule update
    fi

    make clean
    ./autogen.sh --host=$HOST --prefix=$LIBPILIST_RELEASE_PATH --without-cython
    make
    make install

    ####libimobiledevice-glue
    cd $DEPENDENCIES_PATH
    if [ -d "libimobiledevice-glue" ]
    then
        cd libimobiledevice-glue
        git pull
        git submodule init
        git submodule update
    else
        git clone https://github.com/libimobiledevice/libimobiledevice-glue.git
        cd libimobiledevice-glue
        git submodule init
        git submodule update
    fi

    make clean
    ./autogen.sh --host=$HOST --prefix=$LIBIMOBILEDEVICE_GLUE_RELEASE_PATH
    make
    make install

    ####libusbmuxd
    cd $DEPENDENCIES_PATH
    if [ -d "libusbmuxd" ]
    then
        cd libusbmuxd
        git pull
        git submodule init
        git submodule update
    else
        git clone https://github.com/libimobiledevice/libusbmuxd.git
        cd libusbmuxd
        git submodule init
        git submodule update
    fi

    make clean
    ./autogen.sh --host=$HOST --prefix=$LIBUSBMUXD_RELEASE_PATH
    make
    make install

    ####OpenSSL
    cd $DEPENDENCIES_PATH
    if [ -d "OpenSSL-for-iPhone" ]
    then
        cd OpenSSL-for-iPhone
        git pull
        git submodule init
        git submodule update
    else
        git clone https://github.com/x2on/OpenSSL-for-iPhone.git
        cd OpenSSL-for-iPhone
        git submodule init
        git submodule update
    fi

    if [[ $1 == "ios" ]]; then
        if [ -d $OPENSSL_RELEASE_PATH ]
        then
        rm -r $OPENSSL_RELEASE_PATH
        fi

        mkdir $OPENSSL_RELEASE_PATH
        ./build-libssl.sh --version=1.1.1l --targets="ios64-cross-arm64"
        cp -r include $OPENSSL_RELEASE_PATH
        cp -r lib $OPENSSL_RELEASE_PATH
    fi

    ####libimobiledevice
    cd $BASE_PATH
    make clean
    ./autogen.sh --host=$HOST --prefix=$LIBIMOBILEDEVICE_RELEASE_PATH
    make
    make install
}

# build_target "ios"
# build_target "macosx_arm64"
build_target "macosx_x86_64"
# build_libimobiledevice $1
