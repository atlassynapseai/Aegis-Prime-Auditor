import pickle
import subprocess

# Vulnerable: Command injection
user_input = input("Enter command: ")
subprocess.call(user_input, shell=True)

# Vulnerable: Insecure deserialization
data = pickle.loads(user_input)
