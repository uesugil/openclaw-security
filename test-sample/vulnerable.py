#!/usr/bin/env python3
# Test file with intentional vulnerabilities for scanner testing

import pickle
import os
import yaml

# Hardcoded secrets (should be detected)
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
password = "supersecret123"
API_KEY = "sk-1234567890abcdefghij"

# Dangerous eval (should be detected)
def process_input(user_input):
    result = eval(user_input)
    return result

# Pickle loads (should be detected)
def load_data(data):
    return pickle.loads(data)

# YAML load without safe loader (should be detected)
def load_config(yaml_str):
    return yaml.load(yaml_str)

# OS system (should be detected)
def run_command(cmd):
    os.system(cmd)

# SQL injection (should be detected)
def get_user(username):
    query = "SELECT * FROM users WHERE name = '%s'" % username
    cursor.execute(query)

# Weak crypto (should be detected)
import hashlib
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()
