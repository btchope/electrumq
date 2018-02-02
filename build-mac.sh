~/miniconda2/envs/electrumq/bin/python setup-release.py py2app
mkdir -p dist/electrumq.app/Contents/Resources/electrumq/resources/styles
cp -a electrumq/resources/styles/* dist/electrumq.app/Contents/Resources/electrumq/resources/styles