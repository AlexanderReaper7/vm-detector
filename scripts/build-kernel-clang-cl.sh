#!/usr/bin/env bash
# Build the optional x64 WDM probe with an unpacked Microsoft WDK NuGet package.
# No dependency download, signing, installation or boot-setting change occurs.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${WDK_ROOT:?Set WDK_ROOT to the unpacked package c directory}"
: "${WDK_VERSION:?Set WDK_VERSION to its Include/Lib version directory}"
SDK=${WIN_SDK:-/nix/store/nhx2x793lx2d1imnsvbqinlm8070qc2s-win-sdk-17.14.37411.7}
MLBIN=${LLVM_BIN:-/nix/store/iflhifd3p9d04cpvzjw3h9n7r1gj23g4-llvm-21.1.8/bin}
OUT=${1:?Pass the output .sys path}
OBJ=$(mktemp -d)
trap 'rm -rf "$OBJ"' EXIT
"$MLBIN/llvm-ml64" -c -Fo "$OBJ/readcs.obj" kernel/readcs.asm
clang-cl /nologo /c /TC /kernel /O2 /clang:-O3 /clang:-march=native /clang:-mtune=native \
  /clang:-flto /GS- /Zl /D_AMD64_ /DAMD64 /D_WIN64 /D_KERNEL_MODE /DNTDDI_VERSION=0x0A000000 \
  "/I$WDK_ROOT/Include/$WDK_VERSION/km" "/I$WDK_ROOT/Include/$WDK_VERSION/shared" \
  "/I$SDK/sdk/include/shared" "/I$SDK/crt/include" "/I$SDK/sdk/include/ucrt" \
  "/Fo$OBJ/probe.obj" kernel/probe.c
lld-link /driver /dll /subsystem:native /entry:GsDriverEntry /nodefaultlib /machine:x64 \
  /dynamicbase /nxcompat /opt:ref /opt:icf "/out:$OUT" "$OBJ/probe.obj" "$OBJ/readcs.obj" \
  "/libpath:$WDK_ROOT/Lib/$WDK_VERSION/km/x64" ntoskrnl.lib hal.lib wdmsec.lib BufferOverflowK.lib
echo "built unsigned $OUT"
