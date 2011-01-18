import time
import sys
from TaskMonitor import TaskMonitor

def myfunction(taskmon):
	for i in range(0,10):
		mytask = taskmon.new_subtask("Test task %d" % i, 10.0, 0, 50)
		for j in range(0,50):
			time.sleep(0.1)
			mytask.tick()

def cb_task_start(task):
	print task.task_name + ":"

def cb_task_progress(task):
	sys.stdout.write(".")
	sys.stdout.flush()

def cb_task_end(task):
	print ""
	
taskmon = TaskMonitor()
taskmon.add_on_task_start_callback(cb_task_start)
taskmon.add_on_tick_callback(cb_task_progress)
taskmon.add_on_task_end_callback(cb_task_end)

myfunction(taskmon)
print ""
