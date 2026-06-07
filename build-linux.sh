#!/bin/bash
set -e
cd ~/rgm

echo "=== Сборка Linux ==="
make distclean 2>/dev/null || true

# Сбрасываем Windows переменные
unset HOST
unset PREFIX  
unset CONFIG_SITE

./autogen.sh

./configure \
  --disable-tests \
  --disable-bench \
  --with-gui \
  --with-incompatible-bdb \
  --disable-asm \
  LIBOQS_CFLAGS="-I/usr/local/include" \
  LIBOQS_LIBS="-L/usr/local/lib -loqs -lssl -lcrypto"

make -j"$(nproc)" CXXFLAGS="-g -O2 -Wno-maybe-uninitialized -Wno-unused-parameter"

mkdir -p ~/rgm/release/linux
cp src/rgmd src/rgm-cli src/rgm-tx ~/rgm/release/linux/
[ -f src/qt/rgm-qt ] && cp src/qt/rgm-qt ~/rgm/release/linux/
echo "=== Linux бинарники ==="
ls -lh ~/rgm/release/linux/
