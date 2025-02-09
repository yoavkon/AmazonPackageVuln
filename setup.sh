#!/usr/bin/bash

# This script sets up the environment for the
# Python vulnerability scanner on Amazon Linux 2.
# It installs and sets up Python, pip, osquery

source /etc/os-release
if [[ "$ID" != "amzn" && "$VERSION_ID" != "2" ]]; then
    echo "Not running Amazon Linux 2. exiting"
    exit 1
fi

echo "Installing python3 and pip..."
sudo yum install python3 python3-pip git -y

echo "Installing osquery..."
curl -L https://pkg.osquery.io/rpm/GPG | sudo tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
sudo yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo
sudo yum-config-manager --enable osquery-s3-rpm-repo
sudo yum install osquery -y

sudo systemctl enable osqueryd
sudo systemctl start osqueryd

echo "Installing Python modules: osquery, requests, urllib3, argparse"
pip3 install osquery urllib3==1.26.6 requests argparse
