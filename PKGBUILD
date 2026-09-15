# Maintainer: Julian
pkgname=cachy-security-suite
pkgver=1.1.0
pkgrel=1
pkgdesc="Modern PyQt6 graphical security & audit suite for Arch Linux & CachyOS"
arch=('any')
license=('GPL-3.0-or-later')
depends=('python' 'python-pyqt6' 'aur-scanner')
optdepends=('clamav: On-demand antivirus scanning for binaries and downloads')
provides=('aur-scanner-gui')
conflicts=('aur-scanner-gui')
makedepends=('python-setuptools')

package() {
    cd "$srcdir/.."

    # Install main application directory
    install -dm755 "$pkgdir/usr/share/$pkgname"
    cp -r "aur_scanner_gui" "$pkgdir/usr/share/$pkgname/"
    install -Dm755 "main.py" "$pkgdir/usr/share/$pkgname/main.py"

    # Install launcher wrapper
    install -dm755 "$pkgdir/usr/bin"
    cat <<EOF > "$pkgdir/usr/bin/$pkgname"
#!/usr/bin/env bash
exec python3 "/usr/share/$pkgname/main.py" "\$@"
EOF
    chmod 755 "$pkgdir/usr/bin/$pkgname"
    ln -sf "$pkgname" "$pkgdir/usr/bin/aur-scanner-gui"

    # Install icon and desktop files
    install -Dm644 "resources/aur-scanner.svg" "$pkgdir/usr/share/icons/hicolor/scalable/apps/aur-scanner.svg"
    install -Dm644 "resources/aur-scanner-256.png" "$pkgdir/usr/share/icons/hicolor/256x256/apps/aur-scanner.png"
    install -Dm644 "cachy-security-suite.desktop" "$pkgdir/usr/share/applications/cachy-security-suite.desktop"
    install -Dm644 "aur-scanner-gui.desktop" "$pkgdir/usr/share/applications/aur-scanner-gui.desktop"
}
