#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# Usage:
#
#     perf record -a -g -F 99 sleep 1
#     perf script firefox-gecko-converter.py

from __future__ import print_function
import os
import sys
import json
from functools import reduce

sys.path.append(os.environ['PERF_EXEC_PATH'] + \
	'/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import *
from Core import *

USER_CATEGORY_INDEX = 0
KERNEL_CATEGORY_INDEX = 1
thread_map = {}
start_time = None

CATEGORIES = [
    {'name': 'User', 'color': 'yellow', 'subcategories': ['Other']},
    {'name': 'Kernel', 'color': 'orange', 'subcategories': ['Other']}
]

PRODUCT = os.popen('uname -op').read().strip()

def trace_end():
    thread_array = list(map(lambda thread: thread['finish'](), thread_map.values()))
    for thread in thread_array:
        key = thread['samples']['schema']['time']
        thread['samples']['data'].sort(key=lambda data : float(data[key]))

    result = {
        'meta': {
            'interval': 1,
            'processType': 0,
            'product': PRODUCT,
            'stackwalk': 1,
            'debug': 0,
            'gcpoison': 0,
            'asyncstack': 1,
            'startTime': start_time,
            'shutdownTime': None,
            'version': 24,
            'presymbolicated': True,
            'categories': CATEGORIES,
            'markerSchema': []
            },
        'libs': [],
        'threads': thread_array,
        'processes': [],
        'pausedRanges': []
    }
    json.dump(result, sys.stdout, indent=2)

def process_event(param_dict):
	global start_time
	global thread_map
	def _createtread(name, pid, tid):
		markers = {
			'schema': {
				'name': 0,
				'startTime': 1,
				'endTime': 2,
				'phase': 3,
				'category': 4,
				'data': 5,
			},
			'data': [],
		}
		samples = {
			'schema': {
				'stack': 0,
				'time': 1,
				'responsiveness': 2,
				},
			'data': [],
		}
		frameTable = {
			'schema': {
				'location': 0,
				'relevantForJS': 1,
				'innerWindowID': 2,
				'implementation': 3,
				'optimizations': 4,
				'line': 5,
				'column': 6,
				'category': 7,
				'subcategory': 8,
			},
			'data': [],
		}
		stackTable = {
			'schema': {
				'prefix': 0,
				'frame': 1,
			},
			'data': [],
		}
		stringTable = []

		stackMap = dict()
		def get_or_create_stack(frame, prefix):
			key = f"{frame}" if prefix is None else f"{frame},{prefix}"
			stack = stackMap.get(key)
			if stack is None:
				stack = len(stackTable['data'])
				stackTable['data'].append([prefix, frame])
				stackMap[key] = stack
			return stack

		frameMap = dict()
		def get_or_create_frame(frameString):
			frame = frameMap.get(frameString)
			if frame is None:
				frame = len(frameTable['data'])
				location = len(stringTable)
				stringTable.append(frameString)
				category = KERNEL_CATEGORY_INDEX if frameString.find('kallsyms') != -1 \
						or frameString.find('/vmlinux') != -1 \
						or frameString.endswith('.ko)') \
						else USER_CATEGORY_INDEX
				implementation = None
				optimizations = None
				line = None
				relevantForJS = False
				subcategory = None
				innerWindowID = 0
				column = None

				frameTable['data'].append([
					location,
					relevantForJS,
					innerWindowID,
					implementation,
					optimizations,
					line,
					column,
					category,
					subcategory,
				])
				frameMap[frameString] = frame
			return frame

		def addSample(threadName, stackArray, time):
			nonlocal name
			if name != threadName:
				name = threadName
			stack = reduce(lambda prefix, stackFrame: get_or_create_stack
					(get_or_create_frame(stackFrame), prefix), stackArray, None)
			responsiveness = 0
			samples['data'].append([stack, time, responsiveness])

		def finish():
			return {
				"tid": tid,
				"pid": pid,
				"name": name,
				"markers": markers,
				"samples": samples,
				"frameTable": frameTable,
				"stackTable": stackTable,
				"stringTable": stringTable,
				"registerTime": 0,
				"unregisterTime": None,
				"processType": 'default'
			}

		return {
			"addSample": addSample,
			"finish": finish
		}

	def _addThreadSample(pid, tid, threadName, time_stamp, stack):
		thread = thread_map.get(tid)
		if not thread:
			thread = _createtread(threadName, pid, tid)
			thread_map[tid] = thread
		thread['addSample'](threadName, stack, time_stamp)

	time_stamp = (param_dict['sample']['time'] // 1000) / 1000
	pid = param_dict['sample']['pid']
	tid = param_dict['sample']['tid']
	thread_name = param_dict['comm']
	start_time = time_stamp if not start_time else start_time
	if param_dict['callchain']:
		stack = []
		for call in param_dict['callchain']:
			if 'sym' not in call:
				continue
			stack.append(call['sym']['name'] + f' (in {call["dso"]})')
		if len(stack) != 0:
			stack = stack[::-1]
			_addThreadSample(pid, tid, thread_name, time_stamp, stack)
	else:
		mod = param_dict['symbol'] if 'symbol' in param_dict else '[unknown]'
		dso = param_dict['dso'] if 'dso' in param_dict else '[unknown]'
		_addThreadSample(pid, tid, thread_name, time_stamp, [mod + f' (in {dso})'])
