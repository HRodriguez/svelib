# -*- coding: utf-8 -*-
#
#  TaskMonitor.py : Implementation of Task Monitors for PVCryptoLib
#
#  Task Monitors are used to produce progress notifications about actions 
#  executed within PloneVoteCryptoLib.
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

class TaskMonitor:
    """
    Used to monitor the progress of PloneVoteCryptoLib actions.
    
    A TaskMonitor is optionally accepted by most PloneVoteCryptoLib methods 
    which are expected to take a non-negligible time to execute from the point 
    of view of the user. Before passing the TM object, is possible to register 
    callbacks with it, for different events, including:
    
        - The start of a subtask
        - The end of this task or one of its subtasks
        - Each time the task advances X% progress towards completion
          (for tasks in which the percent of the task already completed can be 
          reasonably estimated)
        - Each time the task advances N ticks (minimal steps) towards completion
    
    Callbacks are called whenever the event for which they were registered 
    occurs, receiving the Task Monitor instance that triggered the event as 
    their only argument. Said instance may be the task for which they were 
    registered or a subtask. The callback can then inspect the properties of 
    the task object in order to present some form of progress report to the 
    user (ie. a progress bar).
    
    Callbacks are executed synchronously because of limitations in python's
    multi-threading capabilities (search: Global interpreter lock). It is thus 
    recommended that callbacks be fast functions or called very infrequently, 
    as to not add significantly to the time it takes for the monitored task to 
    complete.
    
    Note: A callback can be registered with the option cascade = False, which 
    means it will only be called for the current task and not any subtasks. 
    However, most tasks only report tick or percent progress in their leaf 
    subtasks (those that have no further subtasks).
    
    Attributes:
       (Attributes are most useful when querying the TM object in callbacks)
        task_name::string    -- Name of the current task or subtask.
        parent::TaskMonitor    -- The task that spawned this subtask.
        percent_of_parent::float    -- How much (in %) does this subtask 
                                      represents of the work done by its parent.
        num_subtasks::int    -- Expected number of subtasks for this task.
        current_subtask::TaskMonitor-- Currently executing subtask of this task.
        current_subtask_num::int    -- Number of the currently executing subtask
        recorded_ticks::int   -- Ticks (steps) that have occurred for this task.
        expected_ticks::int    -- Total ticks expected to occur for this task.
                                (-1 means Unknown)
    """
    
    def provides_percent_monitoring(self):
        """
        Return whether or not this task provides progress percent monitoring.
        
        When this method returns false, get_percent_completed() should always 
        return 0.0 as the percentage already completed.
        
        Returns:
            ans::bool -- True if the task provides information about the 
                         percentage already completed.
                         False if the task does not provide such information.
        """
        return (self.expected_ticks != -1)
    
    def get_percent_completed(self):
        """
        Return the percentage of the task which has already been completed.
        
        If the task monitor does not have information about the expected number 
        of ticks (minimal steps) that it will take for the task to be 
        completed, then 0.0 is returned.
        
        Returns:
            percentage::float   -- The percentage of the task already completed.
        """
        if(self.provides_percent_monitoring()):
            assert (self.expected_ticks >= 0)
            # float division:
            return (100.0 * self.recorded_ticks) / self.expected_ticks
        else:
            return 0.0
            
    
    def __init__(self, task_name="Root", num_subtasks=0, expected_ticks = -1):
        """
        Create a new task monitor associated with a new task or subtask.
        
        Arguments:
            task_name::string   -- The name of the task associated with this TM.
            num_subtasks::int    -- Known or expected number of subtasks for 
                                   the new task.
            expected_ticks::int    -- Expected number of ticks/steps for the 
                                   new task.
        """
        self.task_name = task_name
        self.num_subtasks = num_subtasks
        self.expected_ticks = expected_ticks
        self.recorded_ticks = 0
        self.current_subtask = None
        self.current_subtask_num = 0
        
        self._on_task_start_callbacks = []
        self._on_task_end_callbacks = []
        self._on_tick_callbacks = []
        self._on_progress_percent_callbacks = []

        
    def add_on_task_start_callback(self, callback_function, cascade = True):
        """
        Add a function to be called whenever a subtask starts.
        
        The given function is called whenever the currently executing subtask 
        changes. For example, when the monitored code invokes new_subtask().
        
        Arguments:
            callback_function(task::TaskMonitor)
                -- A callback function which takes a TaskMonitor pointing to 
                   the newly started subtask.
            cascade::bool    -- Whether or not this callback applies to subtasks
        """
        callback = {'function' : callback_function, 'cascade' : cascade}
        self._on_task_start_callbacks.append(callback)

        
    def add_on_task_end_callback(self, callback_function, cascade = True):
        """
        Add a function to be called whenever a subtask finishes.
        
        The given function is called whenever the currently executing subtask 
        ends. For example, when the monitored code invokes new_subtask() over 
        its parent.
        
        This callbacks will always be called before on_task_start callbacks 
        for the same event.
        
        Arguments:
            callback_function(task::TaskMonitor)
                -- A callback function which takes a TaskMonitor pointing to 
                   the recently finished subtask.
            cascade::bool    -- Whether or not this callback applies to subtasks
        """
        callback = {'function' : callback_function, 'cascade' : cascade}
        self._on_task_end_callbacks.append(callback)

    
    def add_on_progress_percent_callback(self, callback_function, \
                                         percent_span = 5.0, cascade = True):
        """
        Add a function to be called each percent_span percentile progress.
        
        The given function is called each time the current task's (or a 
        subtask's) progress increases by the given (percent_span) percent.
        
        Note that if the requested percent granularity is smaller than the 
        granularity of the task "ticks" (ie. a single tick may advance progress 
        by more than one percent_span at a time), then the callback function 
        may be called multiple times in succession without progress occurring 
        in between calls.
        
        Arguments:
            callback_function(task::TaskMonitor)
                -- A callback function which takes a TaskMonitor pointing to 
                   the currently executing task.
            percent_span::float        -- The percentile progress span between 
                                       each time the callback function is 
                                       called. (default: 5%)
            cascade::bool   -- Whether or not this callback applies to subtasks.
        """
        callback = {'function' : callback_function, 'cascade' : cascade, \
                'percent_span' : percent_span, 'next_percent' : percent_span}
        self._on_progress_percent_callbacks.append(callback)

    
    def add_on_tick_callback(self, callback_function, num_ticks = 1, \
                             cascade = True):
        """
        Add a function to be called each num_ticks ticks (steps) of progress.
        
        The given function is called each time the current task's (or a 
        subtask's) progress increases by the given number of ticks.
        
        Arguments:
            callback_function(task::TaskMonitor)
                -- A callback function which takes a TaskMonitor pointing to 
                   the currently executing task.
            num_ticks::int    -- The ticks of progress that must occur between 
                               each time the callback function is called. 
                               (default: one tick)
            cascade::bool    -- Whether or not this callback applies to subtasks
        """
        callback = {'function' : callback_function, 'cascade' : cascade, \
                'num_ticks' : num_ticks}
        self._on_tick_callbacks.append(callback)

    
    def remove_callback(self, callback_function):
        """
        Deletes a callback function.
        
        The given function is deleted from any callback list in which it might 
        be registered for this task or its subtasks.
        
        Note, however, that, if the callback function was registered for a 
        parent task of the current task, it won't be deleted from it and thus 
        will still be called when other subtasks of said parent, which are not 
        part of the current task, execute.
        """
        task = self
        while(task != None):
            for l in [task._on_task_start_callbacks, \
                      task._on_task_end_callbacks, \
                      task._on_progress_percent_callbacks, \
                      task._on_tick_callbacks]:
                for cb in l:
                    if cb['function'] is callback_function:
                        l.remove(cb)
                        
            task = task.current_subtask

    
    def new_subtask(self, name, percent_of_parent = 100.0, num_subtasks=0, 
                    expected_ticks = -1):
        """
        Starts a new subtask to the current one.
        
        Each subtask is associated with a new TaskMonitor object. Cascading 
        callbacks are copied to the subtask.
        
        Arguments:
            name::string    -- The name of the new subtask
            percent_of_parent::float    -- How much, in percentage, does this 
                                    new subtask represent of the parent task.
            num_subtasks::int    -- Known or expected number of subtasks for 
                                   the new task.
            expected_ticks::int    -- Expected number of ticks/steps for the 
                                   new task.
        
        Returns:
            subtask::TaskMonitor    -- The TM for the new subtask.
        """
        # Call task_end callbacks on the current subtask (if there is one) and 
        # any still active subtask of that task, in reverse order (children, 
        # then parent).
        ending_subtasks_stack = []
        tm = self.current_subtask
        
        while(tm != None):
            ending_subtasks_stack.append(tm)
            tm = tm.current_subtask
        
        ending_subtasks_stack.reverse()
        for ending_subtask in ending_subtasks_stack:
            for cb in ending_subtask._on_task_end_callbacks:
                cb["function"](ending_subtask)
        
        # Set up object and parent, child links
        subtask = TaskMonitor(name, num_subtasks, expected_ticks)
        self.current_subtask = subtask
        self.current_subtask_num += 1
        self.num_subtasks = max(self.num_subtasks, self.current_subtask_num)
        subtask.parent = self
        subtask.percent_of_parent = percent_of_parent
        
        
        # Cascade callbacks
        for cb in self._on_task_start_callbacks:
            if cb['cascade']:
                subtask._on_task_start_callbacks.append(cb)
                
        for cb in self._on_task_end_callbacks:
            if cb['cascade']:
                subtask._on_task_end_callbacks.append(cb)
                
        for cb in self._on_progress_percent_callbacks:
            if cb['cascade']:
                # Progress percent callbacks are set for the subtask using 
                # add_on_progress_percent_callback instead of copying the 
                # existing callback record. This is because cb["next_percent"] 
                # must be reset in the subtask while kept intact for the parent 
                # task.
                subtask.add_on_progress_percent_callback(cb["function"],
                                                         cb["percent_span"],
                                                         cascade = True)
                
        for cb in self._on_tick_callbacks:
            if cb['cascade']:
                subtask._on_tick_callbacks.append(cb)
        
        # Call task_start callbacks
        for cb in self._on_task_start_callbacks:
            cb["function"](subtask)        
        
        return subtask

    
    def tick(self):
        """
        Used to indicate to the task monitor that an step of the current task 
        has taken place.
        
        Calling this method registers a new tick in the task represented by 
        this TaskMonitor instance, updates the progress state and calls any 
        relevant registered callbacks.
        """
        self.recorded_ticks += 1
        percent = self.get_percent_completed()
        
        for cb in self._on_tick_callbacks:
            if(self.recorded_ticks % cb["num_ticks"] == 0):
                cb["function"](self)
        
        for cb in self._on_progress_percent_callbacks:
            while(cb["next_percent"] <= percent):
                cb["function"](self)
                cb["next_percent"] += cb["percent_span"]
                
    def end_task(self):
        """
        Used to indicate to the task monitor that the task represented by it 
        has completed.
        
        This method calls all relevant on_task_end callbacks for this task and 
        any still running subtasks. It also removes all callbacks from those 
        tasks, preventing them from being called after the task has ended.
        """
        ending_subtasks_stack = []
        tm = self
        
        # Get all ending tasks
        while(tm != None):
            ending_subtasks_stack.append(tm)
            tm = tm.current_subtask
        
        # For each such task, starting bottom up from children to parent:
        ending_subtasks_stack.reverse()
        for ending_subtask in ending_subtasks_stack:
        
            # Call on_task_end_callbacks
            for cb in ending_subtask._on_task_end_callbacks:
                cb["function"](ending_subtask)
            
            # Remove all callbacks
            ending_subtask._on_task_start_callbacks = []
            ending_subtask._on_task_end_callbacks = []
            ending_subtask._on_progress_percent_callbacks = []
            ending_subtask._on_tick_callbacks = []
