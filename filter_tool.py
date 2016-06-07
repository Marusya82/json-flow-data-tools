# parsing command line like python filter_tool.py -ifolder ../Data/ -BE 5.0 -dp 53 -o stdout
# enchanced command line functionality: -ifilter "dp = 53 and be > 5.0"

import urllib2
import os
import json
import argparse
import re
import pprint
import numpy
import sys

# statistics for how long does the function take
import time
from functools import wraps

# dictionary for enchanced command line functionality
dictionary_operators = { '<': float.__lt__,'>': float.__gt__, '<=': float.__le__, '>=': float.__ge__, '=': float.__eq__}

# to diffirenciate between regular and custom functions
reg_functions = ["float.__lt__", "float.__le__", "float.__eq__", "float.__ge__", "float.__gt__"] 

# open and parse the file for insecure ciphersuites
input_file_cipher = open("sorted.txt", "r")
	
# save all insecure ciphersuites to a list
insecure_list = []

# save all bad ips to the list
bad_ips = []

# statistics to count number of files and flows and print the results
flow_count = 0
flow_wrapper = [flow_count]
file_count = 0
file_wrapper = [file_count]
mylist = []

# global variable to distinguish between "and"/"or" cases
case = False
case_wrapper = [case]

# choose every line with "avoid"
for line in input_file_cipher:
	if (re.match("(.*)(A|a)(V|v)(O|o)(I|i)(D|d)(.*)", line)):
		parsed_line = str.split(line)
		for item in parsed_line:
			if (len(item) == 4):
				insecure_list.append(item)

# open webpage and parse the file for bad ips
#response = urllib2.urlopen("http://talosintel.com/feeds/ip-filter.blf")
#html = response.read()
#bad_ips = str.split(html)
#for item in bad_ips:
#	print item, type(item)
#bad_ips.append('91.220.62.30')

# save all ips to check to a list
ip_list = []

# stats of function calls
PROF_DATA = {}

def profile(fn):
	@wraps(fn)
	def with_profiling(*args, **kwargs):
		
		start_time = time.time()
		ret = fn(*args, **kwargs)

		elapsed_time = time.time() - start_time

		if fn.__name__ not in PROF_DATA:
			PROF_DATA[fn.__name__] = [0, []]
			PROF_DATA[fn.__name__][0] += 1
			PROF_DATA[fn.__name__][1].append(elapsed_time)

			return ret

	return with_profiling

def print_prof_data():
	for fname, data in PROF_DATA.items():
		max_time = max(data[1])
		avg_time = sum(data[1]) / len(data[1])
		#print "Function %s called %d times. " % (fname, data[0]),
		print "Execution time max: %.3f, average: %.3f (seconds)" % (max_time, avg_time)
		if flow_wrapper[0] != 0:
			print "On average function takes %.5f seconds per flow.\n" % (avg_time / flow_wrapper[0])

def clear_prof_data():
	global PROF_DATA
	PROF_DATA = {}

# type(x) = list, type(y) = int, return len(x) > y
def list_len_gt(x, y):
	return (float.__gt__(float(len(x)), y))

# type(x) = str, return True if x is "insecure"
def insecure_cs(x):
	#	print insecure_list
	# if x is in the list - return true
	if x in insecure_list:
		return True

# type(x) = list, return True if exists y in x where y is "insecure"
def contains_insecure(x):
	#	print insecure_list
	for item in x:
		if insecure_cs(item):
			return True

# type(x) = str, return True if x is in the ip_list
def has_ip(x):
	# if x is in the list - return true
	if x in ip_list:
		return True
	else:
		return False

# check if ip is in the malicious ips list
def has_bad_ip(x):
	# if x is in the list - return true
	for item in bad_ips:
		if item == x:
			return True
		else:
			return False

# type(x) = list, returns True if the flow uses a dp/sp contained in list x
def uses_ports(x, value):
	if value in x:
		return True

@profile
def filter_tls(ifolder, criteria):
	# save result
	result = {"appflows": [{}]}
	result_list = []

	count = len(os.listdir(ifolder))
	print count
	
	# apply filter to each file in the folder
	for filename in os.listdir(ifolder):
		
		count -= 1
		print count
		
		# statistics of number of files
		file_wrapper[0] += 1
		
		# clean up the format to load as json
		t_json = ""
		with open(ifolder+filename,'r') as fp:
			for line in fp:
				t_json += line.strip().replace('"x": i','"x": "i"').replace('"x": a','"x": "a"')
				if line.strip() == "]}":
					break
		if not t_json.startswith('{'):
			continue
		if not t_json.endswith("] }") and not t_json.endswith("]}"):
			t_json += "] }"
		try:
			data = json.loads(t_json)
		except Exception as inst:
			#print type(inst)
			#print inst.args
			#print inst
			continue
		
		# statistics of number of flows
		flow_wrapper[0] += len(data["appflows"])
	
		# reset the flag for the next file
		flag = False

		# for each flow apply each criteria filter
		for flow_number in range(len(data["appflows"])):
			
			# save the flow
			flow_test = data["appflows"][flow_number]
				
			for criteria_number in criteria:
				
				# extract every item of a criteria
				json_field = criteria_number[0]
				func = criteria_number[1]
				value = criteria_number[2]
				json_field_value = flow_test["flow"].get(json_field)
			
				# if function is not a custom function cast value of a field to float
				func_split = str.split(str(func))
				if json_field_value is not None:
					if "'float'" in func_split:
						json_field_value = float(json_field_value)
					if value is None:
						func_result = func(json_field_value)
						#print type(json_field_value)
						#print json_field_value
						#print func_result
					else:
						func_result = func(json_field_value, value)
				
				# if field is not present or function returns false - do not save the flow and break the for loop
				if json_field_value is not None:
					if not func_result:
						flag = False
						if case_wrapper[0]:
							break
					else:
						flag = True

				if not case_wrapper[0] and json_field_value is not None and flag:
					result_list.append(flow_test)
				
			if case_wrapper[0] and json_field_value is not None and flag:
				#print case_wrapper[0]
				#print json_field_value
				#print flag
				result_list.append(flow_test)
		
		# save flows
		result["appflows"] = result_list
	
	# save into a file
	with open("data.json", 'w') as f:
		json.dump(result, f, indent = 4, separators = (',', ': '))
		if len(result["appflows"]) > 0:
			print "\nResults are written into 'data.json' file.\n"
		f.close()

	#pprint.pprint(result)
	print "There are %.0f flows that satisfy the given criteria.\n" % len(result["appflows"])
	ip_list = []
	return result

# main funciton
def main():
	# create a list of tuples for filter functionality
	criteria = []

	# parse command line arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("-ifolder", help = "specify path to folder with flows")
	parser.add_argument("-ifilter", help = "specify functionaly of a filter, operands and operators must be separated by spaces")

	args = parser.parse_args()
	
	if args.ifilter:
		
		print "Starting execution..."

		str_split = str.split(args.ifilter)
		
		#print str_split
	
		# check for "and"/"or" case
		if len(str_split) > 3 and str_split[3] == "and":
			case_wrapper[0] = True
		
		# strip the string off "and"/"or"
		str_split = filter(("and").__ne__, str_split)
		str_split = filter(("or").__ne__, str_split)
		
		#print len(str_split)

		# quick check on length of a parsed string
		if len(str_split) % 3 != 0:
			print 'It seems there is something wrong with the -ifilter flag. It should be of the following format:\n"dp = 53"\n"dp = 53 or dp = 443"\n"scs < recommended"\n"be < 1.5 and op > 10"\nTerminating. Try again.'
			sys.exit()

		if str_split[0] == "da" or str_split[0] == "sa":
			ip_list.append(str_split[2])
			#print str_split[0]
			#print len(ip_list)
			flows = filter_tls(args.ifolder, [(str_split[0], has_ip, None)])

		# case for "scs"/"cs" query
		elif args.ifilter == "scs < recommended":
			criteria = [("scs", insecure_cs, None)]	

		#elif args.ifilter == "da = malicious":
		#	criteria = [("da", has_bad_ip, None)]
		
		else:
			criteria = []

			# check for operator in command line ("and" or "or")
			#print str_split

			for i in numpy.arange(0, len(str_split), 3):
				json_field = str_split[i]
				#print json_field
				operator = str_split[i+1]
				#print operator
				operand = float(str_split[i+2])
				# look up a funcion in a dictionary
				func = dictionary_operators.get(operator)
				l = (json_field, func, operand)
				criteria.append(l)
		
	# call the function with provided arguments
	if len(criteria) > 0:
		filter_tls(args.ifolder, criteria)
	
	#flows = filter_tls("/home/marina/DataBackup/Users/", [("dp", float.__eq__, 443), ("be", float.__gt__, 5.0), ("non_norm_stats", list_len_gt, 1)])

	#flows = filter_tls("/home/marina/DataBackup/Users/", [("cs", contains_insecure, None)])
	
	print "Statistics:"
	print "Total number of files scanned: ", file_wrapper[0]
	print "Total number of flows scanned: ", flow_wrapper[0]

	print_prof_data()
	
if __name__ == "__main__":
	   main()
