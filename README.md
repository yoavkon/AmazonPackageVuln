# AmazonPackageVuln
A simple Python script that checks the version of certain
packages and compares them to a known database of
vulnerabilities (such as the NIST NVD)

# Notes
1. Virtual machine running Amazon Linux 2
    - EC2 on the cloud running remotely
    - VirtualBox machine running locally
2. Check software versions
    - Check kernel version using `uname -r`
    - Use `rpm -qa` to list all packages and versions
    - Use `osquery` to query installed software: [osquery Python module](https://pypi.org/project/osquery/)
    - 
3. Compare these versions to a database
    - Use Snyk API
    - Use NIST NVD API
    - Use Amazon Linux Security Center [ALAS](https://alas.aws.amazon.com/alas2.html)

* Amazon apparently uses their own repos for yum
```bash
$ yum reposlist
repo id                         repo name                           status
!amzn2-core/2/x86_64            Amazon Linux 2 core repository      36,942
amzn2-extra-docker/2/x86_64     Amazon Extras repo for docker       137
```

