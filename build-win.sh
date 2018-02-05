## These settings probably don't need change
export WINEPREFIX=/opt/wine64
#export WINEARCH='win32'

PYHOME=c:/python27
PYTHON="wine $PYHOME/python.exe -OO -B"

$PYTHON "C:/pyinstaller/pyinstaller.py" electrumq.spec
wine "$WINEPREFIX/drive_c/Program Files (x86)/NSIS/makensis.exe" /DPRODUCT_VERSION=pre0.0.2 electrumq.nsi

rm ~/work/electrumq.org/_site/download/electrumq-win-pre0.0.2.exe
mv dist/electrumq-setup.exe ~/work/electrumq.org/_site/download/electrumq-win-pre0.0.2.exe


