#!/bin/bash
set -e
cd ~/rgm

echo "=== Сборка Windows ==="
make distclean 2>/dev/null || true
./autogen.sh

export HOST=x86_64-w64-mingw32
export PREFIX="$PWD/depends/$HOST"
export CONFIG_SITE="$PREFIX/share/config.site"
export PATH="$PREFIX/bin:$PATH"

./configure \
  --host=$HOST \
  --prefix="$PREFIX" \
  --disable-tests \
  --disable-bench \
  --with-gui \
  --with-incompatible-bdb \
  --disable-asm \
  LIBOQS_CFLAGS="-I$PREFIX/include" \
  LIBOQS_LIBS="-L$PREFIX/lib -loqs"

make -j2

# Копируем в отдельную папку
mkdir -p ~/rgm/release/windows
cp src/rgmd.exe src/rgm-cli.exe src/rgm-tx.exe ~/rgm/release/windows/
cp src/qt/rgm-qt.exe ~/rgm/release/windows/ 2>/dev/null || true
echo "=== Windows бинарники в ~/rgm/release/windows/ ==="
ls -lh ~/rgm/release/windows/
