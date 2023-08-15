#!/usr/bin/env python3
import re
import sys
import json
from functools import reduce


def isPerfScriptFormat(profile):
    if profile.startswith('# ========\n'):
        return True

    if profile.startswith('{'):
        return False

    firstLine = profile[:profile.index('\n')]
    return bool(re.match(r'^\S.*?\s+(?:\d+/)?\d+\s+(?:\d+\d+\s+)?[\d.]+:', firstLine))

CATEGORIES = [
{'name': 'User', 'color': 'yellow', 'subcategories': ['Other']},
{'name': 'Kernel', 'color': 'orange', 'subcategories': ['Other']}
]
USER_CATEGORY_INDEX = 0
KERNEL_CATEGORY_INDEX = 1

def convertPerfScriptProfile(profile):
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
                # print('batman', frame, frameString)
            
                category = KERNEL_CATEGORY_INDEX if frameString.find('kallsyms') != -1 or frameString.find('/vmlinux') != -1 or frameString.endswith('.ko)') else USER_CATEGORY_INDEX
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
            # TODO: This is a hack to make the profile work with the flamegraph.
            # get_or_create_stack will create a new stack if it doesn't exist, or return the existing stack if it does.
            # get_or_create_frame will create a new frame if it doesn't exist, or return the existing frame if it does.
            stack = reduce(lambda prefix, stackFrame: get_or_create_stack(get_or_create_frame(stackFrame), prefix), stackArray, None)
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

    threadMap = dict()
    def _addThreadSample(pid, tid, threadName, time_stamp, stack):
        thread = threadMap.get(tid)
        if not thread:
            thread = _createtread(threadName, pid, tid)
            threadMap[tid] = thread
        thread['addSample'](threadName, stack, time_stamp)

    lines = profile.split('\n')

    line_index = 0
    startTime = 0
    while line_index < len(lines):
        line = lines[line_index]
        line_index += 1
    # perf script --header outputs header lines beginning with #
        if line == '' or line.startswith('#'):
            continue

        sample_start_line = line

        sample_start_match = re.match(r'^(.*)\s+([\d.]+):', sample_start_line)
        if not sample_start_match:
            print(f'Could not parse line as the start of a sample in the "perf script" profile format: "{sample_start_line}"')
            continue

        before_time_stamp = sample_start_match[1]
        time_stamp = float(sample_start_match[2]) * 1000 
       # print(before_time_stamp)
        threadNamePidAndTidMatch = re.match(r'^(.*)\s+(?:(\d+)\/)?(\d+)\b', before_time_stamp)
        
        if not threadNamePidAndTidMatch:
            print('Could not parse line as the start of a sample in the "perf script" profile format: "%s"' % sampleStartLine)
            continue
    #    print(threadNamePidAndTidMatch)
        threadName = threadNamePidAndTidMatch[1].strip()
        pid = int(threadNamePidAndTidMatch[2] or 0)
    #    print(threadNamePidAndTidMatch[2])
        tid = int(threadNamePidAndTidMatch[3] or 0)
     #   print(int(threadNamePidAndTidMatch[3] or 0))
       # print(threadName, pid, tid)
        if startTime == 0:
            startTime = time_stamp
    # Parse the stack frames of the current sample in a nested loop.
        stack = []
        while line_index < len(lines):
            stackFrameLine = lines[line_index]
            line_index += 1
            if stackFrameLine.strip() == '':
                # Sample ends.
                break
 #           print(stackFrameLine)
            stackFrameMatch = re.match(r'^\s*(\w+)\s*(.+) \(([^)]*)\)', stackFrameLine)
            if stackFrameMatch:
                # pc = stackFrameMatch[1]
                rawFunc = stackFrameMatch[2]
                mod = stackFrameMatch[3]
                rawFunc = re.sub(r'\+0x[\da-f]+$', '', rawFunc)

            if rawFunc.startswith('('):
                continue # skip process names

            if mod:     
                # If we have a module name, provide it.
                # The code processing the profile will search for
                # "functionName (in libraryName)" using a regexp,
                # and automatically create the library information.
                rawFunc += f' (in {mod})'

            stack.append(rawFunc)
            # print(stack)
        if len(stack) != 0:
            stack.reverse()
            _addThreadSample(pid, tid, threadName, time_stamp, stack)

    thread_array = list(map(lambda thread: thread['finish'](), threadMap.values()))

    for thread in thread_array:
        # The samples are not guaranteed to be in order, sort them so that they are.
        key = thread['samples']['schema']['time']
        thread['samples']['data'].sort(key=lambda data : float(data[key]))

    # TODO: return the result
    return {
        'meta': {
            'interval': 1,
            'processType': 0,
            'product': 'Lenovo_yoga',  # TODO: get this from the system
            'stackwalk': 1,
            'debug': 0,
            'gcpoison': 0,
            'asyncstack': 1,
            'startTime': startTime,
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

def main():
#    inputFile = input('Enter input file name: ')
    with open('text_input.txt') as f:
        profile = f.read()
    isPerfScript = isPerfScriptFormat(profile)
    output = convertPerfScriptProfile(profile)
    json.dump(output, sys.stdout, indent=2)
   #     print('isPerfScript: {}'.format(isPerfScript))

if __name__ == '__main__':
    main()
