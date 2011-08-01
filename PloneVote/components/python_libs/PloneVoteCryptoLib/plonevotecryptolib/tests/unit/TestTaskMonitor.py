# -*- coding: utf-8 -*-
#
# ============================================================================
# About this file:
# ============================================================================
#
#  TestTaskMonitor.py : Unit tests for 
#                       plonevotecryptolib/utilities/TaskMonitor.py
#
#  For usage documentation of TaskMonitor.py, see, besides this file:
#    * plonevotecryptolib/tests/doctests/taskmonitor_usage_doctest.txt
#    * the documentation strings for the classes and methods of TaskMonitor.py
#    * the use of the TaskMonitor API inside the test programs/tools in
#      plonevotecryptolib/tools/*.py
#
#  Part of the PloneVote cryptographic library (PloneVoteCryptoLib)
#
#  Originally written by: Lazaro Clapp
#
# ============================================================================
# LICENSE (MIT License - http://www.opensource.org/licenses/mit-license):
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# ============================================================================

import unittest
from plonevotecryptolib.utilities.TaskMonitor import TaskMonitor

# ============================================================================
# Some example "TaskMonitor-enabled" functions:
# (used in the test cases below)
# ============================================================================

def tme_fibonacci(i, task_monitor=None):
    """
    A simple task monitor enabled function that calculates the ith Fibonacci 
    number.
    
    This function has the following properties:
        * Optionally accepts a TaskMonitor object.
        * Given a task monitor, creates a single subtask:
            "Calculating the ${i}th Fibonacci number"
          where ${i} gets the replaced by the value of the argument i.
        * Can report progress to the monitor in percentage as well as ticks. 
    """
    # Check if we got a task monitor
    if(task_monitor):
        subtask_name = "Calculating the %dth Fibonacci number" % i
        # tm will be the TaskMonitor for the fibonacci subtask
        tm = task_monitor.new_subtask(subtask_name, expected_ticks = i + 1)
    
    if(tm): tm.tick() # Add one step to the subtask
    if(i == 0):
        return 0
    
    if(tm): tm.tick() # Add one step to the subtask
    if(i == 1):
        return 1
    
    # n = 2
    n_2 = 0 # Fib(n-2), Fib(0) = 0
    n_1 = 1 # Fib(n-1), Fib(1) = 1
    for j in range(2,i):
        if(tm): tm.tick() # Add one step to the subtask
        temp = n_1
        n_1 += n_2
        n_2 = temp
        
    if(tm): tm.tick() # Add one step to the subtask
    # (at this point, tm should have received i + 1 ticks)
    tm.end_task()
    return n_1 + n_2
    
def tme_search_in_list(l, e, task_monitor=None):
    """
    A simple task monitor enabled function that tries to locate the element e 
    in the list l. If it finds it, it returns the first position at which the 
    element can be found. Otherwise returns -1.
    
    This function has the following properties:
        * Optionally accepts a TaskMonitor object.
        * Given a task monitor, creates a single subtask:
            "Searching for ${e}"
          where ${e} gets the replaced by the value of the argument e.
        * Reports progress only in ticks, since percentage of completion CANNOT 
          be estimated.
          (In a 1000000 element list, e may be found at position #1 or #999999). 
    """
    # Check if we got a task monitor
    if(task_monitor):
        # tm will be the TaskMonitor for the search subtask
        tm = task_monitor.new_subtask("Searching for %s" % e)
    
    for i in range(0,len(l)):
        if(tm): tm.tick()
        if(l[i] == e):
            tm.end_task()
            return i
     
    tm.end_task()
    return -1
    
def tme_fibonacci_subtasks(task_monitor):
    """
    A task monitor enabled function with multiple subtasks and progress 
    percentage reporting.
    """
    tm = task_monitor.new_subtask("Multiple Fibonacci Tasks", num_subtasks=3)
    tm2 = tm.new_subtask("Fibonacci(300)", percent_of_parent = 30.0)
    tme_fibonacci(300, tm2)
    tm2 = tm.new_subtask("Fibonacci(500)", percent_of_parent = 50.0)
    tme_fibonacci(500, tm2)
    tm2 = tm.new_subtask("Fibonacci(200)", percent_of_parent = 20.0)
    tme_fibonacci(200, tm2)
    tm.end_task()
    

# ============================================================================
# Helper classes:
# ============================================================================
    
class Counter:
    def __init__(self): self.value = 0
    def increment(self): self.value += 1

class Logger:
    def __init__(self): self._s = ""
    def __str__(self): return self._s
    def log(self, msg): self._s += msg

# ============================================================================
# The actual test cases:
# ============================================================================

class TestTaskMonitor(unittest.TestCase):
    """
    Test the class: plonevotecryptolib.utilities.TaskMonitor.TaskMonitor
    """
    
    def setUp(self):
        """
        Unit test setup method.
        """
        self.task_monitor = TaskMonitor()
    
    def test_report_ticks(self):
        """
        Test that TaskMonitor can be used to report the number of steps (ticks) 
        performed by a "TaskMonitor-enabled" function.
        """
        # We register a callback that increments a counter by one and is 
        # called every 10 ticks
        counter = Counter()
        self.task_monitor.add_on_tick_callback(lambda tm: counter.increment(), 
                                               num_ticks = 10)
        
        # Now, we call the tme_fibonacci function with our task monitor, asking 
        # for the 100th Fibonacci number
        tme_fibonacci(100, self.task_monitor)
        
        # The counter should have been updated once for every 10 numbers in the 
        # sequence from 0 to our desired number, inclusive. So counter should 
        # be 100/10 = 10.
        self.assertEqual(counter.value, 10)
          
    def test_report_percent(self):
        """
        Test that TaskMonitor can be used to report the completion percentage 
        of a "TaskMonitor-enabled" function that allows percentage monitoring.
        """
        # We register a callback that increments a counter by one and is 
        # called every 5% progress
        counter = Counter()
        self.task_monitor.add_on_progress_percent_callback( \
                            lambda tm: counter.increment(), 
                            percent_span = 5.0)
        
        # Now, we call the tme_fibonacci function with our task monitor, asking 
        # for the 100th Fibonacci number
        tme_fibonacci(100, self.task_monitor)
        
        # The counter should have been updated once for every 5% advance in the 
        # called function. This gives us 20 updates.
        self.assertEqual(counter.value, 20)
        
    def test_task_without_percent_reporting(self):
        """
        Test how add_on_tick_callback(...) *and* 
        add_on_progress_percent_callback(...) work when the task does not 
        provide progress percent reporting (ie. a variable length task).
        """
        # We register a callback that increments a counter by one and is 
        # called every 10 ticks
        counter1 = Counter()
        self.task_monitor.add_on_tick_callback(lambda tm: counter1.increment(), 
                                               num_ticks = 10)
        
        # We register a callback that increments a counter by one and is 
        # called every 5% progress
        counter2 = Counter()
        self.task_monitor.add_on_progress_percent_callback( \
                            lambda tm: counter2.increment(), 
                            percent_span = 5.0)
        
        # Now, we call the tme_search_in_list function with our task monitor, 
        # asking for the position of element 100 in range(0,300)
        tme_search_in_list(range(0,300), 100, self.task_monitor)
        
        # counter1 should have been update 10 times, one for each 10 ticks of 
        # a total of 100 ticks (100 is the 100th element of range(0,300))
        self.assertEqual(counter1.value, 10)
        
        # counter2 should have never been updated, since tme_search_in_list 
        # does not provide progress percent monitoring
        self.assertEqual(counter2.value, 0)
        
    def test_subtask_reporting(self):
        """
        Test complex reporting on a task with subtasks.
        This includes:
            * Test task start/end callbacks.
            * Test getting the name and number of each subtask.
            * Test reporting percent progress of the whole task and each 
              subtask.
        """
        # Construct a logger object
        logger = Logger()
        
        # Set up callbacks to log messages on:
        
        # subtask creation,
        def task_start_cb(tm):
            tm_p = tm.parent
            msg = "New task started: \"%s\" " \
                  "(Subtask #%d of %d for task \"%s\")\n" % \
                  (tm.task_name, tm_p.current_subtask_num, \
                   tm_p.num_subtasks, tm_p.task_name)
            logger.log(msg)
           
        self.task_monitor.add_on_task_start_callback(task_start_cb)
        
        # subtask completion,
        def task_end_cb(tm):
            msg = "Task completed: \"%s\"\n" % tm.task_name
            logger.log(msg)
           
        self.task_monitor.add_on_task_end_callback(task_end_cb)
        
        # and progress percent (20%)
        def task_percent_cb(tm):
            msg = "\"%s\"... %d%% completed.\n" % \
                  (tm.task_name, tm.get_percent_completed())
            logger.log(msg)
           
        self.task_monitor.add_on_progress_percent_callback(task_percent_cb)
        
        # We also count the total number of ticks
        counter = Counter()
        self.task_monitor.add_on_tick_callback(lambda tm: counter.increment(), 
                                               num_ticks = 1)
        
        # Call tme_fibonacci_subtasks using the task monitor
        tme_fibonacci_subtasks(self.task_monitor)
        
        # and compare the logged output with the expected one
        expected_output = \
"""New task started: \"Multiple Fibonacci Tasks\" (Subtask #1 of 1 for task \"Root\")
New task started: \"Fibonacci(300)\" (Subtask #1 of 3 for task \"Multiple Fibonacci Tasks\")
New task started: \"Calculating the 300th Fibonacci number\" (Subtask #1 of 1 for task \"Fibonacci(300)\")
\"Calculating the 300th Fibonacci number\"... 5% completed.
\"Calculating the 300th Fibonacci number\"... 10% completed.
\"Calculating the 300th Fibonacci number\"... 15% completed.
\"Calculating the 300th Fibonacci number\"... 20% completed.
\"Calculating the 300th Fibonacci number\"... 25% completed.
\"Calculating the 300th Fibonacci number\"... 30% completed.
\"Calculating the 300th Fibonacci number\"... 35% completed.
\"Calculating the 300th Fibonacci number\"... 40% completed.
\"Calculating the 300th Fibonacci number\"... 45% completed.
\"Calculating the 300th Fibonacci number\"... 50% completed.
\"Calculating the 300th Fibonacci number\"... 55% completed.
\"Calculating the 300th Fibonacci number\"... 60% completed.
\"Calculating the 300th Fibonacci number\"... 65% completed.
\"Calculating the 300th Fibonacci number\"... 70% completed.
\"Calculating the 300th Fibonacci number\"... 75% completed.
\"Calculating the 300th Fibonacci number\"... 80% completed.
\"Calculating the 300th Fibonacci number\"... 85% completed.
\"Calculating the 300th Fibonacci number\"... 90% completed.
\"Calculating the 300th Fibonacci number\"... 95% completed.
\"Calculating the 300th Fibonacci number\"... 100% completed.
Task completed: \"Calculating the 300th Fibonacci number\"
Task completed: \"Fibonacci(300)\"
New task started: \"Fibonacci(500)\" (Subtask #2 of 3 for task \"Multiple Fibonacci Tasks\")
New task started: \"Calculating the 500th Fibonacci number\" (Subtask #1 of 1 for task \"Fibonacci(500)\")
\"Calculating the 500th Fibonacci number\"... 5% completed.
\"Calculating the 500th Fibonacci number\"... 10% completed.
\"Calculating the 500th Fibonacci number\"... 15% completed.
\"Calculating the 500th Fibonacci number\"... 20% completed.
\"Calculating the 500th Fibonacci number\"... 25% completed.
\"Calculating the 500th Fibonacci number\"... 30% completed.
\"Calculating the 500th Fibonacci number\"... 35% completed.
\"Calculating the 500th Fibonacci number\"... 40% completed.
\"Calculating the 500th Fibonacci number\"... 45% completed.
\"Calculating the 500th Fibonacci number\"... 50% completed.
\"Calculating the 500th Fibonacci number\"... 55% completed.
\"Calculating the 500th Fibonacci number\"... 60% completed.
\"Calculating the 500th Fibonacci number\"... 65% completed.
\"Calculating the 500th Fibonacci number\"... 70% completed.
\"Calculating the 500th Fibonacci number\"... 75% completed.
\"Calculating the 500th Fibonacci number\"... 80% completed.
\"Calculating the 500th Fibonacci number\"... 85% completed.
\"Calculating the 500th Fibonacci number\"... 90% completed.
\"Calculating the 500th Fibonacci number\"... 95% completed.
\"Calculating the 500th Fibonacci number\"... 100% completed.
Task completed: \"Calculating the 500th Fibonacci number\"
Task completed: \"Fibonacci(500)\"
New task started: \"Fibonacci(200)\" (Subtask #3 of 3 for task \"Multiple Fibonacci Tasks\")
New task started: \"Calculating the 200th Fibonacci number\" (Subtask #1 of 1 for task \"Fibonacci(200)\")
\"Calculating the 200th Fibonacci number\"... 5% completed.
\"Calculating the 200th Fibonacci number\"... 10% completed.
\"Calculating the 200th Fibonacci number\"... 15% completed.
\"Calculating the 200th Fibonacci number\"... 20% completed.
\"Calculating the 200th Fibonacci number\"... 25% completed.
\"Calculating the 200th Fibonacci number\"... 30% completed.
\"Calculating the 200th Fibonacci number\"... 35% completed.
\"Calculating the 200th Fibonacci number\"... 40% completed.
\"Calculating the 200th Fibonacci number\"... 45% completed.
\"Calculating the 200th Fibonacci number\"... 50% completed.
\"Calculating the 200th Fibonacci number\"... 55% completed.
\"Calculating the 200th Fibonacci number\"... 60% completed.
\"Calculating the 200th Fibonacci number\"... 65% completed.
\"Calculating the 200th Fibonacci number\"... 70% completed.
\"Calculating the 200th Fibonacci number\"... 75% completed.
\"Calculating the 200th Fibonacci number\"... 80% completed.
\"Calculating the 200th Fibonacci number\"... 85% completed.
\"Calculating the 200th Fibonacci number\"... 90% completed.
\"Calculating the 200th Fibonacci number\"... 95% completed.
\"Calculating the 200th Fibonacci number\"... 100% completed.
Task completed: \"Calculating the 200th Fibonacci number\"
Task completed: \"Fibonacci(200)\"
Task completed: \"Multiple Fibonacci Tasks\"
"""

        self.assertEqual(str(logger), expected_output)
        
        # Including ticks for the 0th number in each succession..
        self.assertEqual(counter.value, 1003)

    def test_remove_callback(self):
        """
        Test the remove_callback method of TaskMonitor.
        """
        # We will run a new Task Monitor to monitor the tme_fibonacci_subtasks 
        # function.
        
        # First, we define a callback to count all ticks for our task
        counter = Counter()
        def tick_counter_cb(tm):
            counter.increment()
         
        self.task_monitor.add_on_tick_callback(tick_counter_cb, 
                                               num_ticks = 1)
                                               
        # Then, we define a callback to be called whenever a subtask starts
        # This callback will remove our previous "tick counter" callback as 
        # soon as the task named "Fibonacci(500)" starts.
        def task_start_cb(tm):
            if(tm.task_name == "Fibonacci(500)"):
                tm.remove_callback(tick_counter_cb)
           
        self.task_monitor.add_on_task_start_callback(task_start_cb)
        
        # Note that since remove_callback removes the callback solely for the 
        # task for which it was called and its subtasks, our tick counter 
        # callback will still be called for the "Fibonacci(200)" subtask of 
        # tme_fibonacci_subtasks.
        
        # Lets run tme_fibonacci_subtasks:
        tme_fibonacci_subtasks(self.task_monitor)
        
        # Check that the counter has registered 301 ticks for Fibonacci(300) 
        # (and subtasks) and 201 for Fibonacci(200) (and subtasks), but no 
        # ticks for Fibonacci(500):
        self.assertEqual(counter.value, 502)


if __name__ == '__main__':
    unittest.main()
