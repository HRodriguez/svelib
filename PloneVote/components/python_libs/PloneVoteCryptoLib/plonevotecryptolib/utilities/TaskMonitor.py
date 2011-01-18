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
	
	ToDo: Explain!
	"""
	
	# General attributes:
	task_name = "Root"
	parent_task = None		# The task of which this task is a subtask
	percent_of_parent = 100.0
	num_subtasks = 0
	current_subtask = None
	recorded_ticks = 0
	expected_ticks = -1
	
	# Callbacks:
	_on_task_change_callbacks = []
	_on_tick_callbacks = []
	_on_progress_percent_callbacks = []
	
	def get_percent_completed(self):
		"""
		Return the percentage of the task which has already been completed.
		
		If the task monitor does not have information about the expected number  
		of ticks (minimal steps) that it will take for the task to be 
		completed, then 0.0 is returned.
		
		Returns:
			percentage::double	-- The percentage of the task already completed.
		"""
		if(expected_ticks == -1):
			return 0.0
		else:
			return (100.0 * recorded_ticks) / expected_ticks	# float division
	
	def __init__(self, task_name="Root", num_subtasks=0, expected_ticks = -1):
		"""
		Create a new task monitor associated with a new task or subtask.
		
		Arguments:
			task_name::string	-- The name of the task associated with this TM.
			num_subtasks::int	-- Known or expected number of subtasks for 
								   the new task.
			expected_ticks::int	-- Expected number of ticks/steps for the new 
								   task.
		"""
		self.task_name = task_name
		self.num_subtasks = num_subtasks
		self.expected_ticks = expected_ticks
		
	def add_on_task_change_callback(self, callback_function, cascade = True):
		"""
		Add a function to be called whenever the current subtask changes.
		
		The given function is called whenever the currently executing subtask 
		changes. For example, when the monitored code invokes new_subtask().
		
		Arguments:
			callback_function(task::TaskMonitor)
				-- A callback function which takes a TaskMonitor pointing to 
				   the newly started subtask.
			cascade::bool	-- Whether or not this callback applies to subtasks.
		"""
		callback = {'function' : callback_function, 'cascade' : cascade}
		self._on_task_change_callbacks.append(callback)
	
	def add_on_progress_percent_callback(self, callback_function, percent_span = 5.0, cascade = True):
		"""
		Add a function to be called each percent_span percentile progress.
		
		The given function is called each time the current task's (or a 
		subtask's) progress increases by the given (percent_span) percent.
		
		Note that if the requested percent granularity is smaller than the 
		granularity of the task "ticks" (ie. a single tick may avance progress 
		by more than one percent_span at a time), then the callback function 
		may be called multiple times in succession without progress occurring 
		in between calls.
		
		Arguments:
			callback_function(task::TaskMonitor)
				-- A callback function which takes a TaskMonitor pointing to 
				   the newly started subtask.
			percent_span::float		-- The percentile progress span between 
									   each time the callback function is 
									   called. (default: 5%)
			cascade::bool	-- Whether or not this callback applies to subtasks.
		"""
		callback = {'function' : callback_function, 'cascade' : cascade, \
				'percent_span' : percent_span, 'next_percent' : percent_span}
		self._on_progress_percent_callbacks.append(callback)
	
	def add_on_tick_callback(self, callback_function, num_ticks = 1, cascade = True):
		"""
		Add a function to be called each num_ticks ticks (steps) of progress.
		
		The given function is called each time the current task's (or a 
		subtask's) progress increases by the given number of ticks.
		
		Arguments:
			callback_function(task::TaskMonitor)
				-- A callback function which takes a TaskMonitor pointing to 
				   the newly started subtask.
			num_ticks::int	-- The ticks of progress that must occur between 
							   each time the callback function is called. 
							   (default: one tick)
			cascade::bool	-- Whether or not this callback applies to subtasks.
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
		for l in [self._on_task_change_callbacks, \
				  self._on_progress_percent_callbacks, \
				  self._on_tick_callbacks]:
			l = [cb for cb in l if cb['function'] is not callback_function]
	
	def new_subtask(self, name, percent_of_parent = 100.0, num_subtasks=0, 
					expected_ticks = -1):
		"""
		Starts a new subtask to the current one.
		
		Each subtask is associated with a new TaskMonitor object. When the 
		current running task creates a new subtask, all callbacks for the 
		current task's monitor are copied to the new subtask's monitor.
		
		Arguments:
			name::string	-- The name of the new subtask
			percent_of_parent::float	-- How much, in percentage, does this 
									new subtask represent of the parent task.
			num_subtasks::int	-- Known or expected number of subtasks for 
								   the new task.
			expected_ticks::int	-- Expected number of ticks/steps for the new 
								   task.
		
		Returns:
			subtask::TaskMonitor	-- The TM for the new subtask.
		"""
		# Set up object and parent, child links
		subtask = TaskMonitor(name, num_subtasks, expected_ticks)
		self.current_subtask = subtask
		subtask.parent = self
		subtask.percent_of_parent = percent_of_parent
		
		# Cascade callbacks
		for cb in self._on_task_change_callbacks:
			if cb['cascade']:
				subtask._on_task_change_callbacks.append(cb)
		for cb in self._on_progress_percent_callbacks:
			if cb['cascade']:
				subtask._on_progress_percent_callbacks.append(cb)
		for cb in self._on_tick_callbacks:
			if cb['cascade']:
				subtask._on_tick_callbacks.append(cb)
		
		# Call task_change callbacks
		for cb in self._on_task_change_callbacks:
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
