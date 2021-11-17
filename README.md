## (Personal) Code Snippets

A github repo maintaining mostly (python) code snippets which I use approximately daily and to save time searching for them in local source code/via google. 

---

#### Creating S3 presigned url with 1 hour expiration time

```python3
import boto3
import botocore


def s3ClientCall():
    return boto3.client('s3')


clientCall      = s3ClientCall()

bucketName = 'test-bucket'
objectName = 'secret.txt'

presignedURL    = clientCall.generate_presigned_url('get_object',
    Params      = {
        'Bucket': bucketName,
        'Key': objectName
    },
		ExpiresIn   = 3600
)

print(presignedURL)
```

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

---

#### Getting STS tokens with export= for CLI - Add in $PATH

```python3
#!/usr/bin/python3


from sys import argv
from os import popen

import json
import argparse


def getMfaSerial(profile):
    if profile == None:
        command     = "aws iam list-mfa-devices --query MFADevices[*].SerialNumber"

    else:
        command     = f"aws iam list-mfa-devices --query MFADevices[*].SerialNumber --profile {profile}"

    try:
        mfaSerial   = json.loads(popen(command).read())
        return(mfaSerial[0])

    except IndexError:
        print("[!] Wrong MFA token for the wrong profile? Maybe?")
        exit(1)


def getSessionTokens(profile, mfaSerial, mfaToken):
    try:
        if profile == None:
            command     = f"aws sts get-session-token --serial-number {mfaSerial} --token {mfaToken}"

        else:
            command     = f"aws sts get-session-token --serial-number {mfaSerial} --token {mfaToken} --profile {profile}"

        token       = json.loads(popen(command).read())["Credentials"]
        return(token)

    except json.decoder.JSONDecodeError:
        exit('[!] Please enter correct MFA!')


def addArguments():
    parser = argparse.ArgumentParser(description='', usage=f'\r[#] Usage: getSTSToken --mfa 123456 --profile default')
    parser._optionals.title = "Basic Help"

    opts = parser.add_argument_group(f'Arguments')
    opts.add_argument('-m', '--mfa',     action="store", dest="mfa",     default=False, help='MFA of the user account')
    opts.add_argument('-p', '--profile', action="store", dest="profile", default=False, help='Access keys profile ( -> default if none given)')

    args = parser.parse_args()
    return(args, parser)


def main():
    args, parser = addArguments()

    if args.mfa:
        mfa = int(args.mfa)

        if args.profile:
            profile = args.profile

        else:
            profile = None

        mfaSerial       = getMfaSerial(profile)
        sessionTokens   = getSessionTokens(profile, mfaSerial, mfa)

        print(f"export AWS_ACCESS_KEY_ID={sessionTokens['AccessKeyId']}")
        print(f"export AWS_SECRET_ACCESS_KEY={sessionTokens['SecretAccessKey']}")
        print(f"export AWS_SESSION_TOKEN={sessionTokens['SessionToken']}")

    else:
        parser.print_help()
        exit()


if __name__ == '__main__':
    main()

```

---

#### Creating layer for AWS Lambda function

```bash
mkdir -p python && \
	cd python && \
	pip install -r ../requirements.txt -t . && \
	cd ../ && \
	zip -rv python.zip python/
```

---

#### Cleaning WSL2 storage after deletion of files (Home edition)

```powershell
wsl --shutdown
diskpart

select vdisk file="C:\Users\Syed Umar Arfeen\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu20.04onWindows_79rhkp1fndgsc\LocalState\ext4.vhdx"
attach vdisk readonly

compact vdisk
detach vdisk
exit
```

---

#### Python Progressbar2 with requests

```bash
pip install progressbar2
```

```python3
import progressbar
import requests


progressbar.streams.wrap_stderr()


def makeRequest(url, path):
    response = requests.get(
        url + path
    )

    if response.status_code == 200:
        print(f"[#] {url}{path} -> {response.status_code}")


def main():
    PATHS = ['/admin', '/adm', '/ad', '/admn', '/a', '/amin', '/ain', '/an', '/dmin', '/post', '/in', '/din', '/amin', '/dmin', '/din', '', '/amin', '/dmin', '/din', '/admi']

    URL = 'https://umar0x01.sh'

    print("[$] Starting direnum...\n")

    for pths, i in zip(PATHS, progressbar.progressbar(range(len(PATHS) - 1), redirect_stdout=True)):
        makeRequest(URL, pths)


if __name__ == '__main__':
    main()
```

---

#### Getting all IPs in a CIDR range using python

```bash
for ips in ipaddress.ip_network('192.168.100.0/24'): print(ips)
```

---

#### Youtube playlist reverse -- python3

```python3
import os

playlist    = "https://www.youtube.com/c/.../videos"
command     = f"youtube-dl -j --flat-playlist --playlist-reverse {playlist} | jq -r '.id' | sed 's_^_https://youtu.be/_'"
print(command)
print()

output      = os.popen(command).read()
print(output)

ytUrls      = []

for count, urls in zip(range(1, 100000), output.strip().split("\n")):
    count   = str(count).zfill(3)
    cmd     = f'youtube-dl -f mp4 -i -v -R 3 --fragment-retries 3 -c -o "{count} - %(title)s.%(ext)s" {urls} --external-downloader "aria2c" --external-downloader-args "-j 10 -s 10 -x 16 --file-allocation=none -c"'
    print(cmd)
```

---

#### VSCode Java remote process debugging using adb port forward

Port forwarding:
```bash
adb jdwp
adb forward tcp:54327 jdwp:3486
```

VS Code config file:
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "type": "java",
            "name": "Debug (Attach)",
            "request": "attach",
            "hostName": "localhost",
            "port": 54327
        }
    ]
}
```

---

#### Basic frida code to bypass root check (owasp uncrackable 1-2)

```javascript
Java.perform(function() {
    var root_lib = Java.use('sg.vantagepoint.a.b');

    root_lib.a.implementation = function() {
        return false;
    }

    root_lib.b.implementation = function() {
        return false;
    }

    root_lib.c.implementation = function() {
        return false;
    }
})
```

---

#### Basic Java code to decrypt AES encrypted base64 encoded string with IV/Key

```java
import java.io.PrintStream;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class RaceCondition {
    public static String decrypt(String valueData) {
        try {
            IvParameterSpec iv = new IvParameterSpec("fedcba9876543210".getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec("0123456789abcdef".getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(2, skeySpec, iv);
            byte[] temp = Base64.getDecoder().decode(valueData);
            return new String(Base64.getDecoder().decode(cipher.doFinal(temp)));
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        System.out.println(decrypt("sqCDT4L+YF5hHNPj9hTgzWuuyXOTFruD8LfbyIs/nlYgeaVZMWZmXeQknnHzAQhKCdREPXfXAX3nSp1HgFJmKw=="));
    }
}
```

---

#### Decrypting AES encrypted b64 encoded string when you've to convert IV/SecretKey into bytes

```java
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

class LayerTwo {
    static byte[] decrypt_text(byte[] ivBytes, byte[] keyBytes, byte[] bytes) throws Exception {
        AlgorithmParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(2, newKey, ivSpec);
        return cipher.doFinal(bytes);
    }

    public static byte[] decrypt(String ivStr, String keyStr, String base64_text) throws Exception {
        byte[] base64_text_decoded = Base64.getDecoder().decode(base64_text);
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(ivStr.getBytes());

        byte[] ivBytes = md.digest();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(keyStr.getBytes());
        return decrypt_text(ivBytes, sha.digest(), base64_text_decoded);
    }

    public static void main(String[] args) {
        try {
            // Ip address
            // "admin_name":"Sm0e+2JxJqOeXWQo0ZdZiQ==","admin_pass":"w9SEXEWvemvKS3PdVvfKBQ=="
            String ip_address = "9I3aP8MS/VKnzPKbx7swGxaMfaoGF0GEbSq64KZFsyg=";
            byte[] decrypted_text = decrypt("Lahore", "WelcomeToLahore", ip_address);
            String decryted_text_into_string = new String(decrypted_text, StandardCharsets.UTF_8);
            System.out.println(decryted_text_into_string);
        }

        catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

---

#### Frida snippet to intercept remove syscall from native library of android and return 000 (so file doesn't get deleted) - By Mukarram bhai

```javascript
Interceptor.attach(Module.getExportByName('libnative-lib.so', 'remove'), {
    onEnter: function (args) {
        args[0] = ptr('000');
    },
    onLeave: function (retval) {
        console.log("++++++++++++++++++++++");
    }
});
```
