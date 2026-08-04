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

# Bypass sharun's AT_BASE=0 bug which breaks Frida-gum's module enumeration.
# This compiles a memory patch and injects it into libfrida-core-1.0.so
cat << 'EOF' > ./AppDir/.patch.cpp
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <link.h>
#include <optional>
#include <span>
#include <string_view>

extern "C" char **environ;

namespace {

using Auxv = ElfW(auxv_t);
using Phdr = ElfW(Phdr);

inline constexpr unsigned long kAuxvTypeMax = 63;
inline constexpr std::size_t kAuxvMax = 128;

// RAII wrapper for a C stdio handle (keeps us exception-free).
class File {
public:
  File(const char *path, const char *mode) noexcept
      : f_(std::fopen(path, mode)) {}
  ~File() {
    if (f_)
      std::fclose(f_);
  }
  File(const File &) = delete;
  File &operator=(const File &) = delete;
  explicit operator bool() const noexcept { return f_ != nullptr; }
  [[nodiscard]] FILE *get() const noexcept { return f_; }

private:
  FILE *f_;
};

// Values to reflect into the auxv (from the dynamic linker's own bookkeeping).
struct Objects {
  const Phdr *exe_phdr = nullptr;
  ElfW(Half) exe_phnum = 0;
  std::optional<std::uintptr_t> interp_base;
};

// The kernel's ORIGINAL [stack] region + an interpreter-base fallback.
struct StackRegion {
  std::uintptr_t start = 0, end = 0;
};
struct MapsInfo {
  StackRegion stack;
  std::optional<std::uintptr_t> interp_base;
};

// Plausible auxv start? Reaches AT_NULL through only small type ids and
// contains AT_PHDR — rejects a spurious needle match on stack data.
[[nodiscard]] bool auxv_looks_valid(const Auxv *a,
                                    std::uintptr_t end) noexcept {
  bool seen_phdr = false;
  for (int n = 0; reinterpret_cast<std::uintptr_t>(a + 1) <= end && n < 512;
       ++a, ++n) {
    if (a->a_type == AT_NULL)
      return seen_phdr;
    if (a->a_type > kAuxvTypeMax)
      return false;
    if (a->a_type == AT_PHDR)
      seen_phdr = true;
  }
  return false;
}

// Find auxv[0] inside the original [stack]: anchor on the AT_PHENT entry
// (value == sizeof(Phdr)), then walk back one entry at a time until the
// preceding a_type is a huge value, meaning we crossed into the envp array.
[[nodiscard]] Auxv *find_orig_auxv(StackRegion s) noexcept {
  Auxv needle{};
  needle.a_type = AT_PHENT;
  needle.a_un.a_val = sizeof(Phdr);

  for (auto addr = s.end - sizeof(needle); addr >= s.start; addr -= 8) {
    if (std::memcmp(reinterpret_cast<void *>(addr), &needle, sizeof(needle)) !=
        0)
      continue;

    auto *cur = reinterpret_cast<Auxv *>(addr);
    while (reinterpret_cast<std::uintptr_t>(cur) > s.start &&
           cur[-1].a_type <= kAuxvTypeMax)
      --cur;

    if (auxv_looks_valid(cur, s.end))
      return cur;
  }
  return nullptr;
}

// auxv reachable from environ — the pivoted/live stack.
[[nodiscard]] Auxv *find_live_auxv() noexcept {
  char **p = environ;
  if (!p)
    return nullptr;
  while (*p)
    ++p;
  return reinterpret_cast<Auxv *>(p + 1);
}

// A bounded view of an auxv array (element count capped by `end`).
[[nodiscard]] std::span<Auxv> auxv_view(Auxv *a, std::uintptr_t end) noexcept {
  if (!a)
    return {};
  return {a, (end - reinterpret_cast<std::uintptr_t>(a)) / sizeof(Auxv)};
}

// Rewrite the program-header and interpreter entries of one auxv in place.
void patch_auxv(std::span<Auxv> av, const Objects &o) noexcept {
  for (auto &e : av) {
    if (e.a_type == AT_NULL)
      break;
    switch (e.a_type) {
    case AT_PHDR:
      e.a_un.a_val = reinterpret_cast<std::uintptr_t>(o.exe_phdr);
      break;
    case AT_PHNUM:
      e.a_un.a_val = o.exe_phnum;
      break;
    case AT_PHENT:
      e.a_un.a_val = sizeof(Phdr);
      break;
    case AT_BASE:
      if (o.interp_base)
        e.a_un.a_val = *o.interp_base;
      break;
    default:
      break;
    }
  }
}

[[gnu::constructor]] void patch() noexcept {
  // Gather the kernel's original [stack] (+ interpreter-base fallback).
  // An IIFE so the whole multi-step scan collapses into one const value.
  const MapsInfo maps = []() noexcept {
    MapsInfo info;
    File f("/proc/self/maps", "r");
    if (!f)
      return info;

    char *line = nullptr;
    std::size_t cap = 0;
    while (::getline(&line, &cap, f.get()) != -1) {
      unsigned long start, end, offset;
      int path_off = -1;
      // start-end perms offset dev inode  pathname
      if (std::sscanf(line, "%lx-%lx %*s %lx %*s %*s %n", &start, &end, &offset,
                      &path_off) != 3 ||
          path_off < 0)
        continue;

      const std::string_view path(line + path_off);
      if (!info.interp_base && offset == 0 && path.contains("ld-linux"))
        info.interp_base = static_cast<std::uintptr_t>(start);
      if (path.contains("[stack]"))
        info.stack = {static_cast<std::uintptr_t>(start),
                      static_cast<std::uintptr_t>(end)};
    }
    std::free(line);
    return info;
  }();

  // Resolve the correct phdr / interpreter values via the linker. IIFE so
  // `o` is const, with the dl_iterate_phdr callback inlined as a captureless
  // lambda right where it is used. (On GCC 13+/Clang 16+ mark the inner
  // lambda `static` — a C++23 nicety this toolchain doesn't yet accept.)
  const Objects o = [&]() noexcept {
    Objects tmp;
    dl_iterate_phdr(
        [](dl_phdr_info *info, std::size_t, void *data) noexcept -> int {
          auto *out = static_cast<Objects *>(data);
          const std::string_view name = info->dlpi_name ? info->dlpi_name : "";
          // Main exe == empty-name link-map entry; it IS the target.
          if (name.empty()) {
            out->exe_phdr = info->dlpi_phdr;
            out->exe_phnum = info->dlpi_phnum;
          } else if (name.contains("ld-linux")) {
            out->interp_base = static_cast<std::uintptr_t>(info->dlpi_addr);
          }
          return 0;
        },
        &tmp);
    if (!tmp.interp_base)
      tmp.interp_base = maps.interp_base;
    return tmp;
  }();

  if (!o.exe_phdr)
    return; // nothing correct to write

  // Primary fix: the kernel's original [stack]. frida-gum locates its auxv
  // by matching "[stack]" in /proc/self/maps and scanning backward, so this
  // abandoned copy is the ONLY one it ever reads.
  Auxv *live = find_live_auxv();
  if (maps.stack.start && maps.stack.end) {
    Auxv *orig = find_orig_auxv(maps.stack);
    if (orig)
      patch_auxv(auxv_view(orig, maps.stack.end), o);
    if (live && live != orig) // keep the live stack sane too
      patch_auxv({live, kAuxvMax}, o);
  } else if (live) {
    patch_auxv({live, kAuxvMax}, o);
  }
}

} // namespace
EOF
g++ -std=c++23 -O2 -fPIC -shared -fno-exceptions -fno-rtti -Wall -Wextra -static-libstdc++ -static-libgcc ./AppDir/.patch.cpp -o ./AppDir/bin/libpatch.so

patchelf --add-needed libpatch.so ./AppDir/bin/libfrida-core-1.0.so

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
