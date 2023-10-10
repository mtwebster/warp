#!/usr/bin/python3

import sys
import os
import subprocess

srcdir = sys.argv[1]
outdir = sys.argv[2]

print("Building grpc s:%s, t:%s" % (srcdir, outdir))

# Older python versions < 3.10 don't have CompileError.
# grpc/src/python/grpcio/support.py uses this.
try:
    from setuptools.errors import CompileError
except ImportError:
    import setuptools.errors
    setuptools.errors.CompileError = distutils.errors.CompileError

try:
    os.chdir(srcdir)
    os.environ["GRPC_PYTHON_BUILD_EXT_COMPILER_JOBS"] = "2"
    subprocess.run(["python3", "setup.py", "build"])
    subprocess.run("cp -r python_build/lib*/grpc %s" % outdir, shell=True)
except Exception as e:
    print(e)
    sys.exit(1)

sys.exit(0)