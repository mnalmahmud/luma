# Sets FRIDA_LINK_ARGS to the swift-build flags needed to link a static
# frida-core. Source this with PKG_CONFIG_PATH already pointing at both
# frida-core-1.0.pc and the staged SDK.
#
# A static frida-core lists gee, gum, soup, quickjs and the rest under
# Requires.private/Libs.private. SwiftPM reads Requires.private for its
# cflags but drops its libs on the floor, and never parses Libs.private
# at all:
#
#   self.cFlags = parser.cFlags + dependencyFlags.cFlags + privateDependencyFlags.cFlags
#   self.libs   = parser.libs   + dependencyFlags.libs
#       -- swift-package-manager Sources/PackageLoading/PkgConfig.swift
#
# So the headers resolve and ~1600 symbols do not. pkg-config --static
# expands exactly what SwiftPM skipped, so hand that to the linker.

FRIDA_LINK_ARGS=
for _flag in $(pkg-config --static --libs frida-core-1.0); do
    case $_flag in
        # A driver flag; ld would reject it, and Swift already links pthread.
        -pthread) ;;
        # Also driver-level: -Xlinker reaches ld directly, where the -Wl,
        # prefix is not a thing, so unwrap it into its comma-separated parts.
        -Wl,*)
            for _part in $(printf '%s' "${_flag#-Wl,}" | tr ',' ' '); do
                FRIDA_LINK_ARGS="$FRIDA_LINK_ARGS -Xlinker $_part"
            done
            ;;
        *) FRIDA_LINK_ARGS="$FRIDA_LINK_ARGS -Xlinker $_flag" ;;
    esac
done
unset _flag _part

test -n "$FRIDA_LINK_ARGS"
