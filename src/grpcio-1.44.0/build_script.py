#!/usr/bin/python3

import sys
import os


srcdir = sys.argv[1]
outdir = sys.argv[2]

print("Building grpc s:%s, t:%s" % (srcdir, outdir))

try:
    os.chdir(srcdir)
    os.system("python3 setup.py build")
    os.system("cp -r python_build/lib*/grpc %s" % outdir)
except Exception as e:
    print(e)
    sys.exit(1)

sys.exit(0)