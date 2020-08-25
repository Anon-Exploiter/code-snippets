"""
Usage of multiprocessing within python3

While passing arguments to the function, we need to provide it with [list] data type. In
case your program doesn't provide you with a list to work with, you can create one yourself
using the following method:

[variable] * 10

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