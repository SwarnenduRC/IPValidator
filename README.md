# NokiaIPValidator - A simple multi threaded program to read a text file of IP addresses and returns the counts of unique IPV4, IPV6 addresses along with total IPV4/IPV6 addresses present in the file. It also gives a count of invalid IP addresses present in the text file

# At present in it's simplest form it will only validate any IP address which doesn't contain any space or special character between each segment. Although it can be easily enhaced.

# This program will work on any compiler (Windows or Linux, prefrebly 64 bit) which supports C++-17
# The program itslef a self explanatory with proper doxygen style comments wherever necessary

# It runs a consumer thread in a continous loop to check whether any line is read from the file and processes it as soon as it gets a hold on the data queue.
# Once both the data queue is empty and the file reader thread is over it exits.
