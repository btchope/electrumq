rm -rf build
rm -rf dist

~/miniconda2/envs/electrumq/bin/python setup-release.py py2app

version=pre0.0.2

cd dist
tar -czf electrumq-mac-$version.tar.gz electrumq.app
rm ~/work/electrumq.org/_site/download/electrumq-mac-$version.tar.gz
mv electrumq-mac-$version.tar.gz ~/work/electrumq.org/_site/download/
cd ..