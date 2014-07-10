import sys

#sys.argv[0] is filename of script, counts as first argument
# start cmd line args at sys.argv[1}

print "The name of this script is {}".format(sys.argv[0])
print "User supplied {} args at run time".format(len(sys.argv))

for arg in sys.argv[1:]:
	print arg
	
while True:
	try:
		if len(sys.argv) == 1:
			ulimit = raw_input("Type a positive integer")
			ulimit = int(ulimit)
			break
		else:
			ulimit = int(sys.argv[1])
			break
	except ValueError:
			print "Integers Only! Try Again!"
			ulimit = raw_input("Type a positive integer")
			ulimit = int(ulimit)
			break

for i in range(0,ulimit):
	i = i+1
	if i % 3 == 0 and i % 5 == 0:
		print "fizzbuzz"
	elif i % 3 == 0:
		print "fizz"
	elif i % 5 == 0:
		print "buzz"
	else:
		print i