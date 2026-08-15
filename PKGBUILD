# Maintainer: ExposureMG <exposuremg@protonmail.com>
pkgname=gxbuild3
pkgver=3.1.0
pkgrel=1
pkgdesc="Xbox 360 image builder"
arch=('x86_64')
url="https://github.com/GxOSS/gxbuild3"
license=('BSD-3-Clause')
makedepends=(
  'make'
  'git'
  'cmake'
)
source=("$pkgname::git+https://github.com/GxOSS/gxbuild3.git#tag=$pkgver")
sha256sums=('SKIP')

build() {
  cd "$srcdir/$pkgname"
  git submodule update --init --recursive
  cmake -S . -B build -G "Unix Makefiles"
  cd build
  make
}

package() {
  cd "$srcdir/$pkgname/build"
  install -Dm755 "gxbuild3" -t "$pkgdir/usr/bin"
}