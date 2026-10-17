#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

VERSION="1.1.0"
REPO="donniexyz/go-fuzzpot"
DATE=$(date -u +"%Y-%m-%d")
BUILDDIR="/tmp/fuzzpot-build-$VERSION"
rm -rf "$BUILDDIR" "$BUILDDIR-release"
mkdir -p "$BUILDDIR"

echo "=== Step 1: Verify build ==="
go build -o /dev/null .
echo "Build OK"

echo "=== Step 2: Cross-compile all binaries ==="
# Format: GOOS/GOARCH/suffix
platforms=(
  "linux/amd64/fuzzpot-linux-amd64"
  "linux/386/fuzzpot-linux-386"
  "linux/arm64/fuzzpot-linux-arm64"
  "linux/arm-7/fuzzpot-linux-armv7"
  "linux/arm-6/fuzzpot-linux-armv6"
  "windows/amd64/fuzzpot-windows-amd64.exe"
  "windows/386/fuzzpot-windows-386.exe"
  "freebsd/amd64/fuzzpot-freebsd-amd64"
  "freebsd/386/fuzzpot-freebsd-386"
  "freebsd/arm64/fuzzpot-freebsd-arm64"
  "darwin/amd64/fuzzpot-darwin-amd64"
  "darwin/arm64/fuzzpot-darwin-arm64"
)

# Clean old zips
rm -f fuzzpot-*.zip

for entry in "${platforms[@]}"; do
  IFS='/' read -r GOOS GOARCH OUTPUT <<< "$entry"
  echo "  → $GOOS/$GOARCH"
  if [ "$GOARCH" = "arm-7" ]; then
    export GOOS GOARCH=arm GOARM=7
  elif [ "$GOARCH" = "arm-6" ]; then
    export GOOS GOARCH=arm GOARM=6
  else
    export GOOS GOARCH
    unset GOARM
  fi
  CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$VERSION" -trimpath -o "$BUILDDIR/$OUTPUT" .
done

# Create zip files
cd "$BUILDDIR"
for entry in "${platforms[@]}"; do
  IFS='/' read -r GOOS GOARCH OUTPUT <<< "$entry"
  zipname="${OUTPUT%.*}-$VERSION.zip"
  zip "$zipname" "$OUTPUT"
done
unset GOOS GOARCH GOARM
cd "$SCRIPT_DIR"

echo "=== Step 3: Git commit & tag ==="
git add -A
git commit -m "v1.1.0: multi-platform port scanning + packaging" || true
git tag -f "v$VERSION"
git push origin master --tags

echo "=== Step 4: Create GitHub release ==="
# Get upload URL from gh release create
gh release delete "v$VERSION" --yes 2>/dev/null || true

# Create release notes
cat > "$BUILDDIR/notes.md" << 'NOTES_EOF'
## What's New in v1.1.0

### 🔧 Multi-Platform Port Scanning
- **Linux**: `/proc/net/tcp` + `/proc/net/tcp6` (unchanged)
- **FreeBSD**: `sockstat` / `netstat` with `sysctl` ephemeral range detection
- **Windows**: `netstat -an` with `netsh` dynamic port range detection
- **Fallback** (other OS): `net.Listen` probe for universal compatibility

### 📦 Native Packages
- `.deb` (Debian/Ubuntu)
- `.rpm` (RHEL/CentOS/Fedora)
- `.apk` (Alpine Linux)
- `.tar.gz` (generic Linux)
- `.zip` (Windows/macOS)

### 🖥️ New Platforms
- **macOS** binaries (amd64 + arm64)

### 🏗️ Code Structure
Split port scanning into platform-specific files with Go build tags:
- `portscan_linux.go` — Linux-specific procfs scanning
- `portscan_freebsd.go` — FreeBSD sockstat/netstat scanning
- `portscan_windows.go` — Windows netstat/netsh scanning
- `portscan_other.go` — Universal fallback (net.Listen probe)
- `portscan.go` — Shared PortManager logic

All binaries are statically linked with zero runtime dependencies.
NOTES_EOF

gh release create "v$VERSION" \
  --title "v1.1.0 — Multi-Platform Port Scanning" \
  --notes-file "$BUILDDIR/notes.md" \
  "$BUILDDIR"/*.zip

echo "=== Step 5: Create .deb package (Debian/Ubuntu) ==="
DEBDIR="$BUILDDIR/deb"
mkdir -p "$DEBDIR/DEBIAN"
mkdir -p "$DEBDIR/usr/bin"
mkdir -p "$DEBDIR/etc/fuzzpot"
mkdir -p "$DEBDIR/var/log/fuzzpot"
mkdir -p "$DEBDIR/usr/lib/systemd/system"
mkdir -p "$DEBDIR/DEBIAN"

cp "$BUILDDIR/fuzzpot-linux-amd64" "$DEBDIR/usr/bin/fuzzpot"
cp config/config.yaml "$DEBDIR/etc/fuzzpot/config.yaml"

cat > "$DEBDIR/DEBIAN/control" << EOF
Package: fuzzpot
Version: $VERSION
Section: net
Priority: optional
Architecture: amd64
Maintainer: dozaibot <dev@dozaibot.com>
Description: Mass Port Payload Sink Honeypot
 A lightweight honeypot that listens on thousands of ports simultaneously,
 capturing attacker payloads with zero external dependencies. Features
 automatic port conflict detection, cross-platform support, and structured
 JSON logging.
Homepage: https://github.com/$REPO
Depends: libc6 (>= 2.17)
EOF

cat > "$DEBDIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e
# Create system user if not exists
if ! id -u fuzzpot &>/dev/null; then
  useradd -r -s /usr/sbin/nologin -d /var/lib/fuzzpot fuzzpot
fi
chown fuzzpot:fuzzpot /var/log/fuzzpot
chmod 755 /var/log/fuzzpot
systemctl daemon-reload
echo "fuzzpot installed. Edit /etc/fuzzpot/config.yaml then run: systemctl enable --now fuzzpot"
EOF
chmod 755 "$DEBDIR/DEBIAN/postinst"

cat > "$DEBDIR/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e
systemctl stop fuzzpot 2>/dev/null || true
systemctl disable fuzzpot 2>/dev/null || true
EOF
chmod 755 "$DEBDIR/DEBIAN/prerm"

cat > "$DEBDIR/DEBIAN/postrm" << 'EOF'
#!/bin/bash
set -e
if [ "$1" = "purge" ]; then
  userdel fuzzpot 2>/dev/null || true
  rm -rf /var/log/fuzzpot /etc/fuzzpot /var/lib/fuzzpot
fi
systemctl daemon-reload
EOF
chmod 755 "$DEBDIR/DEBIAN/postrm"

cat > "$DEBDIR/usr/lib/systemd/system/fuzzpot.service" << 'EOF'
[Unit]
Description=FuzzPot Honeypot
After=network.target
Documentation=https://github.com/donniexyz/go-fuzzpot

[Service]
Type=simple
User=fuzzpot
ExecStart=/usr/bin/fuzzpot -config /etc/fuzzpot/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

dpkg-deb --build "$DEBDIR" "$BUILDDIR/fuzzpot_${VERSION}_amd64.deb"
echo "  → fuzzpot_${VERSION}_amd64.deb"

echo "=== Step 6: Create .rpm package (RHEL/CentOS/Fedora) ==="
RPMDIR="$BUILDDIR/rpm"
mkdir -p "$RPMDIR/SPECS" "$RPMDIR/SOURCES" "$RPMDIR/BUILD" "$RPMDIR/RPMS"

cp "$BUILDDIR/fuzzpot-linux-amd64" "$RPMDIR/SOURCES/fuzzpot"
cp config/config.yaml "$RPMDIR/SOURCES/config.yaml"
cp "$BUILDDIR/deb/usr/lib/systemd/system/fuzzpot.service" "$RPMDIR/SOURCES/fuzzpot.service"

cat > "$RPMDIR/SPECS/fuzzpot.spec" << EOF
Name: fuzzpot
Version: ${VERSION#v}
Release: 1%{?dist}
Summary: Mass Port Payload Sink Honeypot

License: MIT
URL: https://github.com/$REPO
Source0: fuzzpot
Source1: config.yaml
Source2: fuzzpot.service

Requires: systemd

%description
A lightweight honeypot that listens on thousands of ports simultaneously,
capturing attacker payloads with zero external dependencies.

%install
install -Dm755 %{SOURCE0} %{buildroot}/usr/bin/fuzzpot
install -Dm644 %{SOURCE1} %{buildroot}/etc/fuzzpot/config.yaml
install -Dm644 %{SOURCE2} %{buildroot}/usr/lib/systemd/system/fuzzpot.service
install -dm755 %{buildroot}/var/log/fuzzpot

%pre
getent group fuzzpot >/dev/null || groupadd -r fuzzpot
getent passwd fuzzpot >/dev/null || useradd -r -g fuzzpot -d /var/lib/fuzzpot -s /sbin/nologin fuzzpot
exit 0

%post
%systemd_post fuzzpot.service
echo "fuzzpot installed. Edit /etc/fuzzpot/config.yaml then run: systemctl enable --now fuzzpot"

%preun
%systemd_preun fuzzpot.service

%postun
%systemd_postun fuzzpot.service

%files
/usr/bin/fuzzpot
/etc/fuzzpot/config.yaml
/usr/lib/systemd/system/fuzzpot.service
%dir /var/log/fuzzpot
EOF

which rpmbuild &>/dev/null && rpmbuild --define "_topdir $RPMDIR" -bb "$RPMDIR/SPECS/fuzzpot.spec" && cp "$RPMDIR/RPMS/x86_64"/*.rpm "$BUILDDIR/" && echo "  → $(ls $BUILDDIR/*.rpm 2>/dev/null | xargs basename)" || echo "  ⚠ rpmbuild not available, creating rpm manually with fpm or skipping"

# Fallback: create minimal rpm using rpm tool if rpmbuild fails
if ! ls "$BUILDDIR"/*.rpm &>/dev/null && which fpm &>/dev/null; then
  fpm -s dir -t rpm -n fuzzpot -v "${VERSION#v}" \
    --description "Mass Port Payload Sink Honeypot" \
    --url "https://github.com/$REPO" \
    --license MIT \
    --vendor dozaibot \
    "$BUILDDIR/fuzzpot-linux-amd64=/usr/bin/fuzzpot" \
    "config/config.yaml=/etc/fuzzpot/config.yaml" \
    "$BUILDDIR/deb/usr/lib/systemd/system/fuzzpot.service=/usr/lib/systemd/system/fuzzpot.service"
  cp fuzzpot*.rpm "$BUILDDIR/"
  echo "  → $(ls $BUILDDIR/*.rpm | xargs basename)"
fi

echo "=== Step 7: Create .apk package (Alpine Linux) ==="
APKDIR="$BUILDDIR/apk"
mkdir -p "$APKDIR/usr/bin" "$APKDIR/etc/fuzzpot" "$APKDIR/var/log/fuzzpot"

cp "$BUILDDIR/fuzzpot-linux-amd64" "$APKDIR/usr/bin/fuzzpot"
cp config/config.yaml "$APKDIR/etc/fuzzpot/config.yaml"

# Build APK data and control tarballs
cd "$APKDIR"
tar czf "$BUILDDIR/fuzzpot-${VERSION#v}-x86_64.apk" usr/ etc/ var/
cd "$SCRIPT_DIR"
echo "  → fuzzpot-${VERSION#v}-x86_64.apk (data tarball — use with abuild for signed package)"

echo "=== Step 8: Create .tar.gz (generic Linux) ==="
TARDIR="$BUILDDIR/tar"
mkdir -p "$TARDIR/fuzzpot-$VERSION/bin" "$TARDIR/fuzzpot-$VERSION/etc" "$TARDIR/fuzzpot-$VERSION/log"
cp "$BUILDDIR/fuzzpot-linux-amd64" "$TARDIR/fuzzpot-$VERSION/bin/fuzzpot"
cp config/config.yaml "$TARDIR/fuzzpot-$VERSION/etc/config.yaml"
cp "$BUILDDIR/deb/usr/lib/systemd/system/fuzzpot.service" "$TARDIR/fuzzpot-$VERSION/fuzzpot.service"
cp README.md "$TARDIR/fuzzpot-$VERSION/"
cp LICENSE "$TARDIR/fuzzpot-$VERSION/"

tar czf "$BUILDDIR/fuzzpot-${VERSION#v}-linux-amd64.tar.gz" -C "$TARDIR" "fuzzpot-$VERSION"
echo "  → fuzzpot-${VERSION#v}-linux-amd64.tar.gz"

echo "=== Step 9: Create checksums ==="
cd "$BUILDDIR"
sha256sum fuzzpot*.{zip,deb,rpm,apk,gz,tar.gz} 2>/dev/null > "fuzzpot-${VERSION}-checksums.txt" || true
echo "  → fuzzpot-${VERSION}-checksums.txt"

echo "=== Step 10: Upload packages to GitHub release ==="
cd "$SCRIPT_DIR"

# Upload all package files
for f in "$BUILDDIR"/fuzzpot_*.deb "$BUILDDIR"/fuzzpot_*.apk "$BUILDDIR"/fuzzpot-*.tar.gz "$BUILDDIR"/fuzzpot-*.rpm "$BUILDDIR"/fuzzpot-*-checksums.txt; do
  [ -f "$f" ] && gh release upload "v$VERSION" "$f" --clobber && echo "  uploaded $(basename $f)"
done

echo ""
echo "========================================="
echo "  v$VERSION release complete!"
echo "========================================="
echo ""
ls -lh "$BUILDDIR"/*.{zip,deb,apk,gz,rpm,txt} 2>/dev/null
