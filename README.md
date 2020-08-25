## (Personal) Code Snippets

A github repo maintaining (mostly) python code snippets which I use approximately daily and to save time searching for them in local source code/via google. 

#### Usage of multiprocessing in Python3
Source Code: [Link](https://github.com/Anon-Exploiter/code-snippets/blob/master/python3-multiprocessing/py-multiprocessing.py)

```python
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

PROCESSES 	= 10

def goToSleep(time):
	sleep(time)
	print(f"[#] Slept for {time} seconds!")

with concurrent.futures.ProcessPoolExecutor(max_workers = PROCESSES) as executor:
	executor.map(goToSleep, [2] * 50)
```
