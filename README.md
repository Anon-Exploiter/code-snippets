## (Personal) Code Snippets

A github repo maintaining (mostly) python code snippets which I use approximately daily and to save time searching for them in local source code/via google. 

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
