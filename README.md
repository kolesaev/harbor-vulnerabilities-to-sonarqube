# Description

This solution converts Harbor Vulnerabilities JSON report to SonarQube format. 

As Harbor Report doesn't contain file paths, you will need to add one path, which will be used for each issue, eg issuesfile=package.json

This will set issue name the same as issue ID, but you are able to get issue Title via OpenCVE API, just add your OpenCVE login and password into your command via opencveuser=login opencvepassword=password

# Usage

Example
```
python3 harbor-to-sonar.py harborreport=harbor-report.json issuesfile=build.gradle.kts
```

Get Title via OpenCVE API
```
python3 harbor-to-sonar.py harborreport=harbor-report.json issuesfile=package.json opencveuser=opencve-user-login opencvepassword=opencve-user-password
```

# Requirements

OS packages:
- python3

Pip packages:
- requests
