# AmazonPackageVuln
A simple Python script that checks the version of certain  
packages and compares them to a known database of
vulnerabilities (such as the NIST NVD)

# Initial Notes
1. Virtual machine running Amazon Linux 2
    - EC2 on the cloud running remotely
    - VirtualBox machine running locally
2. Check software versions
    - Check kernel version using `uname -r`
    - Use `rpm -qa` to list all packages and versions
    - Use `osquery` to query installed software: [osquery Python module](https://pypi.org/project/osquery/)
3. Compare these versions to a database
    - Use Snyk API [Snyk DB](https://security.snyk.io/)
    - Use [NIST NVD API](https://nvd.nist.gov/developers/vulnerabilities)
    - Use Amazon Linux Security Center [ALAS](https://alas.aws.amazon.com/alas2.html)

* Amazon apparently uses their own repos for yum
```bash
$ yum reposlist
repo id                         repo name                           status
!amzn2-core/2/x86_64            Amazon Linux 2 core repository      36,942
amzn2-extra-docker/2/x86_64     Amazon Extras repo for docker       137
```

# Problems I encountered
I needed to find a way to list all installed packages. 
At first, I considered just using the built in `rpm` package manager.
The command `rpm -qa` lists all packages and their respective versions
in a pretty unfriendly format
```bash
$ rpm -qa
python3-libs-3.7.16-1.amzn2.0.9.x86_64
python3-pip-20.2.2-1.amzn2.0.8.noarch
...
```

To solve this, I needed some kind of universal format for these packages,
that would allow me to look them up on the database.
The [CPE](https://cpe.mitre.org/specification/) specification standardizes the
naming method for software.

Here is an example of an API request using the CPE standard:
```bash
curl 'https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:freebsd:freebsd:3.5.1'
```
The format looks something like this: `cpe:2.3:o:vendor:product:version`
This format is required for NVD, however it is tricky to convert from an RPM package to a CPE.
I ended up finding a different API, which allows to look for vulnerabilities in specific packages.



```bash
yum updateinfo list all
```
