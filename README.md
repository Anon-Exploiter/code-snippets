## (Personal) Code Snippets

A github repo maintaining (mostly) python code snippets which I use approximately daily and to save time searching for them in local source code/via google. 

#### Usage of multiprocessing in Python3
Complete snippet: [Link](https://github.com/Anon-Exploiter/code-snippets/blob/master/python3-multiprocessing/py-multiprocessing.py)
```python
import concurrent.futures
from time import sleep

PROCESSES 	= 10

def goToSleep(time):
	sleep(time)
	print(f"[#] Slept for {time} seconds!")

with concurrent.futures.ProcessPoolExecutor(max_workers = PROCESSES) as executor:
	executor.map(goToSleep, [2] * 50)
```
