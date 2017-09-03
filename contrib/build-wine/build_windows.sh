## These settings probably don't need change
export WINEPREFIX=/opt/wine64
#export WINEARCH='win32'

PYHOME=c:/python27
PYTHON="wine $PYHOME/python.exe -OO -B"

# Let's begin!
cd `dirname $0`
set -e

cd ../../
rm -rf dist/electrumq

$PYTHON "C:/pyinstaller/pyinstaller.py" electrumq.py