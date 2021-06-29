## (Personal) Code Snippets

A github repo maintaining mostly (python) code snippets which I use approximately daily and to save time searching for them in local source code/via google. 

---

#### Usage of multiprocessing in Python3

```python3
"""
Usage of multiprocessing within python3

While passing arguments to the function, we need to provide it with [list] data type. In
case your program doesn't provide you with a list to work with, you can create one yourself
out of a variable using the following method:

[variable] * 10 == [variable(0), variable(1), variable(2), ... variable(9)]

`max_workers` is the number of processes to launch.
"""

import concurrent.futures
from time import sleep

PROCESSES   = 10

def goToSleep(time):
    sleep(time)
    print(f"[#] Slept for {time} seconds!")

with concurrent.futures.ProcessPoolExecutor(max_workers = PROCESSES) as executor:
    executor.map(goToSleep, [2] * 50)
```

---

#### Return week day today from the start of the year

```python3
"""
Return week day today from the start of the year
Right now it's: 35
"""

import datetime

def returnWeekNumber():
    weekNumber = datetime.date.today().isocalendar()[1]
    return(str(weekNumber))
```

---

#### Return list[] of dates from today to past days (e.g: 7 days from now to past) 

```python3
"""
Return list[] of dates from today to past days, such as 7 days from now to past:
['25-08-2020', '24-08-2020', '23-08-2020', '22-08-2020', '21-08-2020', '20-08-2020', '19-08-2020']

Can further reverse the list by [::-1] to get past -> present
"""

import datetime

def returnDates():
    numdays = 7
    date_list = [ (datetime.date.today() - datetime.timedelta(days=_)).strftime('%d-%m-%Y')
            for _ in range(numdays)]
    return(date_list)
```

---

#### Reading file from a S3 bucket using access keys directly through variables (I know it's unsecure :P)

```python3
"""
Reading file from a S3 bucket using access keys directly through 
variables (I know it's unsecure :P)

Takes region of the bucket, the bucket, file to read, access key and secret access key
"""

import boto3

def readFileFromS3(region, bucket, file, ACCESS_KEY, SECRET_KEY):
    s3 = boto3.resource('s3',
        region_name             = region,
        aws_access_key_id       = ACCESS_KEY,
        aws_secret_access_key   = SECRET_KEY,
    )

    bucket = s3.Object(bucket, file)
    body = bucket.get()['Body'].read().decode()

    return(body)

sourceCode  = readFileFromS3(region='eu-west-1', bucket='test-bucket', file='test.json', 
                                ACCESS_KEY='', SECRET_KEY='')
print(sourceCode)
```

---

#### Parsing XLSX file and returning columns in `list(tuple(N, Z))` format

```python3
"""
Parses XLSX file using xlrd module (to be installed through pypi)
Returns `column 0` and `column 2` from the XLSX sheet in the 
form of list[tuple(1, 2), tuple(3, 4), .... tuple(N, Z)]

Takes filename of the excel (xlsx) sheet as input
"""

import xlrd

def parseXLSX(xlsxFile):
    results = []
    wb      = xlrd.open_workbook(xlsxFile) 
    sheet   = wb.sheet_by_index(0) 
    sheet.cell_value(0, 0) 

    for i in range(sheet.nrows): 
        _date   = sheet.cell_value(i, 0).strip()
        _type   = sheet.cell_value(i, 2).strip()

        count.append( (_date, _type) )

    return(count)

xlsxFileName    = 'test.xlsx'
dateAndTypes    = parseXLSX(xlsxFileName)
for _tuples in dateAndTypes:
    print(_tuples)
```

---

#### Simple function to write a preformatted Slack JSON to a Webhook

```python3
"""
Simple function to write a preformatted Slack JSON to a Webhook
Takes the webhook URL and preformatted JSON as input
"""

import requests

def postSlackPost(webhook, slackPost):
    request     = requests.post(webhook,
        headers = {
            'Content-type': 'application/json', 
        },
        json    = slackPost,
    )

    print(request)
    print(request.status_code)
    print(request.text)

webhook     = "https://hooks.slack.com/services/XXXXXXX/XXXXXX/XXXXXXXXXXXXXXXXXX"
slackPost   = {
    "text": "Hello, world!"
}

postSlackPost(webhook, slackPost)
```

---

#### Uploading of (text) files in Discord channel through webhooks

```python3
"""
Python3 snippet allowing uploading of (text) files in discord server's
channel through webhook
"""

import os 
import requests
import datetime

def postFileOnDiscord(webhook, fileName):
	with open(fileName, 'r') as f: fileContents = f.read().strip()

	discordText	= {"content": fileContents}
	response	= requests.post(webhook, json = discordText)

	if response.status_code == 204:
		print(f"[#] File {fileName} posted in channel!")

	else:
		print(f"[!] There was a issue uploading {fileName} in the channel!\nTrace:\n")
		print(response.status_code)
		print(response.headers)
		print(response.text)

def main():
	webhook 	= "https://discordapp.com/api/webhooks/xxxxxxxxxxxxxxx/xxxxxxxxx"
	fileName 	= "/etc/passwd"

	postFileOnDiscord(webhook, fileName)

if __name__ == '__main__':
	main()
```

---

#### Uploading files to Slack `channels` through `Bot` using `cURL` with `OAuth Access Token`

```bash
curl -v -i -s -k -X $'POST' \
-H $'Host: slack.com' \
-H $'Accept: */*' \
-H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64)' \
-H $'Origin: https://api.slack.com' \
-H $'Sec-Fetch-Site: same-site' \
-H $'Sec-Fetch-Mode: cors' \
-H $'Sec-Fetch-Dest: empty' \
-H $'Accept-Language: en-US,en;q=0.9,la;q=0.8' \
-H $'Connection: close' \
-F file=@backup.7z \
  $'https://slack.com/api/files.upload?token=xoxp-xxx-xxx-xxx-xxxx&channels=myFiles&pretty=1'
```

---

#### Creating commands for downloading torrent files, one at a time with aria2c, upload on gdrive, **remove some stuff**
Created for myself, read the code before using it!

```python3
from sys import argv
import os

gDdriveID   = argv[2]
bucket      = argv[2]

def returnIdAndName(torrentFile, grep):
    command         = f"aria2c --show-files {torrentFile}"
    results         = os.popen(command).read().strip().split("\n")

    res             = []

    for data in results:
        if grep in data:
            res.append(data)

    for stuff in res:
        count, fileNames = stuff.strip().split("|")
        command     = f"set -x && aria2c --seed-time=0 --max-upload-limit=1K --seed-ratio=0.0 --select-file {count} {argv[1]} && gupload -r {gDdriveID} \"{fileNames}\" && rm -rfv *"
        # command   = f"set -x && aria2c --file-allocation=none --seed-time=0 --max-upload-limit=1K --seed-ratio=0.0 --select-file {count} {argv[1]} && aws s3 cp \"{fileNames}\" \"s3://{bucket}/\" --endpoint-url=https://s3.wasabisys.com --no-sign-request && rm -rfv *"
        print(command)

def main():
    torrentFile     = argv[1]
    grep            = ".mkv"

    returnIdAndName(torrentFile, grep)

if __name__ == '__main__':
    main()
```

---

#### Preventing certificate warning with requests/urllib3 while using proxy

```python3
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
```

---

#### Installing docker (and adding user in docker group)

```bash
sudo apt-get -y update && \
    sudo apt-get -y install apt-transport-https ca-certificates curl gnupg-agent software-properties-common && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add - && \
    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" && \
    sudo apt-get -y update && \
    sudo apt-get -y install docker-ce docker-ce-cli containerd.io && \
    sudo usermod -aG docker $USER
```

---

#### Downloading PDFs (lectures) from Virtual University

```python3
import requests
import os

for lesson in range(1, 22 + 1):
    url     = f'https://vulms.vu.edu.pk/Courses/PHY101/Lessons/Lesson_{lesson}/Lecture{str(lesson).zfill(2)}.pdf'
    print(url)

    command = f'aria2c -s 10 -j 10 -x 16 -c --file-allocation=none "{url}"'
    os.system(command)
```
