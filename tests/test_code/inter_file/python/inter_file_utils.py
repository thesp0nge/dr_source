# File 1: utils_lib.py
import os

def vulnerable_execute(cmd):
    # The sink is here, but the taint comes from outside
    os.system(cmd)

def safe_execute(cmd):
    # No sink here, or sanitized
    print(f"Executing: {cmd}")
