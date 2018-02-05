rm -rf build
~/miniconda2/envs/electrumq/bin/python setup-release.py py2app
mkdir -p dist/electrumq.app/Contents/Resources/electrumq/resources/styles
cp -a electrumq/resources/styles/* dist/electrumq.app/Contents/Resources/electrumq/resources/styles

sh contrib/build-wine/build_windows.sh

cd dist
tar -czf electrumq-mac-pre0.0.1.tar.gz electrumq.app
rm ~/work/electrumq.org/_site/download/electrumq-mac-pre0.0.1.tar.gz
mv electrumq-mac-pre0.0.1.tar.gz ~/work/electrumq.org/_site/download/
cd ..


rm ~/work/electrumq.org/_site/download/electrumq-win-pre0.0.1.exe
mv build/electrumq/electrumq.exe ~/work/electrumq.org/_site/download/electrumq-win-pre0.0.1.exe


