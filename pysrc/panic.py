import sys
import traceback

def panic(msg):
    print(msg)
    traceback.print_stack()
    sys.exit(0)

