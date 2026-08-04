#!/bin/sh

set -eu

ARCH=$(uname -m)
VERSION=${LUMA_VERSION:-1.0.0}

echo "Installing package dependencies..."
echo "---------------------------------------------------------------"
pacman -Syu --noconfirm libgee libadwaita webkitgtk-6.0 libepoxy libzip libnice patchelf

echo "Installing debloated packages..."
echo "---------------------------------------------------------------"
get-debloated-pkgs --add-common --prefer-nano

mkdir -p ./AppDir/
bsdtar -xOf ./luma-$VERSION-ubuntu-26.04-x86_64.deb data.tar.zst | bsdtar -xf - --strip-components=2 -C ./AppDir/

mkdir -p ./AppDir/bin/
mv -f ./AppDir/lib/luma/luma ./AppDir/bin/luma
patchelf --set-rpath '$ORIGIN/../lib/luma:$ORIGIN/../lib/luma/swift' ./AppDir/bin/luma

export ARCH VERSION
export OUTPATH=$(pwd)
export ADD_HOOKS="self-updater.hook"
export UPINFO="gh-releases-zsync|${GITHUB_REPOSITORY%/*}|${GITHUB_REPOSITORY#*/}|latest|*$ARCH.AppImage.zsync"
export ICON=./AppDir/share/icons/hicolor/512x512/apps/re.frida.Luma.png
export DESKTOP=./AppDir/share/applications/re.frida.Luma.desktop
export STARTUPWMCLASS=re.frida.Luma
export GTK_CLASS_FIX=1

quick-sharun ./AppDir/bin/*

quick-sharun --make-appimage
