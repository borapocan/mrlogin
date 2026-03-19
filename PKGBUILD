# Maintainer: Bora Poçan - mborapocan@gmail.com
pkgname=mrlogin
pkgver=1.0
pkgrel=1
pkgdesc="MrLogin - MrRobotOS Display Manager with PAM Authentication"
arch=('x86_64')
license=('MIT')
depends=('libx11' 'libxft' 'pam' 'fontconfig' 'freetype2' 'otf-font-awesome')
makedepends=('gcc' 'make')
source=("mrlogin.c" "mrlogin.service" "mrlogin.pam" "Makefile")
sha256sums=('SKIP' 'SKIP' 'SKIP' 'SKIP')

build() {
    cd "$srcdir"
    make
}

package() {
    cd "$srcdir"
    install -Dm755 mrlogin "$pkgdir/usr/local/bin/mrlogin"
    install -Dm644 mrlogin.service "$pkgdir/etc/systemd/system/mrlogin.service"
    install -Dm644 mrlogin.pam "$pkgdir/etc/pam.d/mrlogin"
}
