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
mv -f ./AppDir/lib/luma/* ./AppDir/bin/
rm -rf ./AppDir/lib

# Bypass sharun AT_BASE=0 bug which breaks Frida-gum's module enumeration.
# This compiles a memory patch and injects it into libfrida-core-1.0.so
cat << 'EOF' > sharun.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>

__attribute__((constructor))
void sharun() {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return;
    
    unsigned long luma_base = 0;
    unsigned long ld_base = 0;
    unsigned long stack_start = 0, stack_end = 0;
    char line[512];
    
    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) continue;
        
        if (strstr(line, "bin/luma") && strstr(line, " 00000000 ") && !luma_base) {
            luma_base = start;
        }
        if (strstr(line, "ld-linux") && strstr(line, " 00000000 ") && !ld_base) {
            ld_base = start;
        }
        if (strstr(line, " [stack]")) {
            stack_start = start;
            stack_end = end;
        }
    }
    fclose(f);
    
    if (!stack_start || !luma_base || !ld_base) return;
    
    Elf64_auxv_t needle;
    needle.a_type = AT_PHENT;
    needle.a_un.a_val = sizeof(Elf64_Phdr);
    
    Elf64_auxv_t *auxv_start = NULL;
    for (unsigned long addr = stack_end - sizeof(needle); addr >= stack_start; addr -= 8) {
        if (memcmp((void*)addr, &needle, sizeof(needle)) == 0) {
            Elf64_auxv_t *curr = (Elf64_auxv_t *)addr;
            while ((unsigned long)curr >= stack_start) {
                if (curr->a_type > 50 && curr->a_type != AT_SECURE && curr->a_type != AT_RANDOM && curr->a_type != AT_EXECFN) break;
                curr--;
            }
            auxv_start = curr + 1;
            break;
        }
    }
    
    if (auxv_start) {
        for (Elf64_auxv_t *curr = auxv_start; (unsigned long)curr < stack_end; curr++) {
            if (curr->a_type == AT_BASE) {
                curr->a_un.a_val = ld_base;
            } else if (curr->a_type == AT_PHDR) {
                Elf64_Ehdr *ehdr = (Elf64_Ehdr *)luma_base;
                curr->a_un.a_val = luma_base + ehdr->e_phoff;
            } else if (curr->a_type == AT_NULL) {
                break;
            }
        }
    }
}
EOF
gcc -shared -fPIC -o ./AppDir/bin/libsharun.so sharun.c
rm sharun.c

patchelf --add-needed ./AppDir/bin/libsharun.so ./AppDir/bin/libfrida-core-1.0.so

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
