#!/usr/bin/env bash
# Build al-khaser x64 on NixOS with the LLVM/clang-cl cross toolchain (no MSVC,
# no msbuild: the box has clang-cl + lld-link + llvm-ml64 against an xwin-style
# Windows SDK, and dotnet msbuild cannot drive a v143 C++ .vcxproj anyway).
#
# Handles three things a case-insensitive Windows filesystem hides:
#   1. header case: al-khaser includes e.g. "AntiVM/VMware.h" but the file is
#      VMWare.h, and the SDK ships iphlpapi.h where the source wants Iphlpapi.h.
#      A shim dir of symlinks at the as-written path fixes both.
#   2. import-lib case: #pragma comment(lib,"Mpr.lib") vs the on-disk Mpr.Lib.
#   3. MASM: the .asm files assemble with llvm-ml64. AntiDisassm_x64.asm needed
#      two source fixes (unique L_END labels per proc; `call $+5` -> a label),
#      both byte-identical, committed in the tree.
#
# Output: $OUT/al-khaser.exe (default /tmp/al-khaser.exe).
set -euo pipefail
cd "$(dirname "$0")/../al-khaser"

SDK=${WIN_SDK:-/nix/store/nhx2x793lx2d1imnsvbqinlm8070qc2s-win-sdk-17.14.37411.7}
MLBIN=${LLVM_BIN:-/nix/store/iflhifd3p9d04cpvzjw3h9n7r1gj23g4-llvm-21.1.8/bin}
OUT=${1:-/tmp/al-khaser.exe}
INCDIRS=("$SDK/crt/include" "$SDK/sdk/include/ucrt" "$SDK/sdk/include/um" "$SDK/sdk/include/shared" "$SDK/sdk/include/winrt")
LIBDIRS=("$SDK/crt/lib/x64" "$SDK/sdk/lib/um/x64" "$SDK/sdk/lib/ucrt/x64")

SHIM=$(mktemp -d); LIBSHIM=$(mktemp -d); OBJ=$(mktemp -d)
trap 'rm -rf "$SHIM" "$LIBSHIM" "$OBJ"' EXIT

# 1. header case shim: every distinct quoted/needed include, resolved case-insensitively
grep -rhoE '#include[[:space:]]*"[^"]+"' . --include=*.cpp --include=*.h \
  | sed -E 's/#include[[:space:]]*"//; s/"$//' | sort -u > "$OBJ/incs.txt"
printf 'Iphlpapi.h\nWbemidl.h\n' >> "$OBJ/incs.txt"
while read -r P; do
  [ -z "$P" ] && continue; [ -e "./$P" ] && continue
  real=$(find . -ipath "./$P" -type f | head -1)
  if [ -z "$real" ]; then b=$(basename "$P"); for d in "${INCDIRS[@]}"; do real=$(find "$d" -maxdepth 1 -iname "$b" -type f | head -1); [ -n "$real" ] && break; done; fi
  [ -n "$real" ] && { mkdir -p "$SHIM/$(dirname "$P")"; ln -sf "$(readlink -f "$real")" "$SHIM/$P"; }
done < "$OBJ/incs.txt"

# 2. import-lib case shim
for L in Iphlpapi.lib Mpr.lib powrprof.lib Psapi.lib setupapi.lib Shlwapi.lib Slwga.lib \
         wbemuuid.lib Winmm.lib Ws2_32.lib user32.lib advapi32.lib ole32.lib oleaut32.lib shell32.lib; do
  for d in "${LIBDIRS[@]}"; do r=$(find "$d" -maxdepth 1 -iname "$L" | head -1); [ -n "$r" ] && { ln -sf "$(readlink -f "$r")" "$LIBSHIM/$L"; break; }; done
done

# 3. assemble the x64 MASM
"$MLBIN/llvm-ml64" -c -Fo "$OBJ/int2d.obj" AntiDebug/int2d_x64.asm
"$MLBIN/llvm-ml64" -c -Fo "$OBJ/antidisassm.obj" AntiDisassm/AntiDisassm_x64.asm

# compile + link (the 65 vcxproj sources minus pch.cpp, resolved to real case)
mapfile -t RAW < <(grep -oE 'ClCompile Include="[^"]*"' al-khaser.vcxproj | sed 's/ClCompile Include=//; s/"//g' | tr '\\' '/')
SRCS=(); for f in "${RAW[@]}"; do [ "$f" = "pch.cpp" ] && continue
  [ -f "$f" ] && SRCS+=("$f") || SRCS+=("$(find . -ipath "./$f" -type f | head -1 | sed 's#^\./##')"); done

clang-cl /nologo /std:c++17 /EHsc /O2 /MT /DNDEBUG /D_CONSOLE /DWIN32 /DUNICODE /D_UNICODE \
  /Y- /FIpch.h "/I$SHIM" /I. \
  "${SRCS[@]}" "$OBJ/int2d.obj" "$OBJ/antidisassm.obj" \
  "/Fe:$OUT" \
  /link /subsystem:console user32.lib advapi32.lib ole32.lib oleaut32.lib shell32.lib \
  "/libpath:$LIBSHIM" "/libpath:$SDK/crt/lib/x64" "/libpath:$SDK/sdk/lib/um/x64" "/libpath:$SDK/sdk/lib/ucrt/x64"
echo "built $OUT"
