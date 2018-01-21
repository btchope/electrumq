#! /usr/bash
wget http://repo.continuum.io/miniconda/Miniconda3-3.7.0-Linux-x86_64.sh -O ~/miniconda.sh
bash ~/miniconda.sh -b -p $HOME/miniconda
export PATH="$HOME/miniconda/bin:$PATH"

conda install pyqt=4.11.4
conda install appdirs=1.4.3
conda install backports-abc=0.5
conda install certifi=2017.7.27.1
conda install ecdsa=0.13
conda install pbkdf2=1.3
conda install pyaes=1.6.0
conda install pycrypto=2.6.1
conda install pyperclip=1.5.27
conda install qrcode=5.3
conda install singledispatch=3.4.0.3
conda install six=1.10.0
conda install tornado=4.5.2
conda install enum34=1.1.6