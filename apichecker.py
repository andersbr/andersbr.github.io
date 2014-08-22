#!/bin/python
# Script to monitor Apigee RMP nodes

from requests import get
from fabric.api import settings, run, env

user = 'root'
password = 'AuthApigee!'

mgmt_port = 8080
router_port = 8081
mp_port = 8082

mgmt_ip = "15.184.35.241"
mgmt_result = ""
rmp_list = ["15.184.35.217","15.184.35.226","15.184.35.236"]
mp_results = []
router_results = []

def check_mgmt():
   mgmt_path = "http://" + mgmt_ip + ":8080/v1/servers/self/up"
   mgmt_result = get(mgmt_path)
   print mgmt_path
   print mgmt_result
def check_router(rmp_list):
   for node in rmp_list:
       router_path = "http://" + node + ":8081/v1/servers/self/up"
       print router_path
       router_results.append(get(router_path))
       print get(router_path)

def check_mp(rmp_list):
   for node in rmp_list:
       mp_path = "http://" + node + ":8082/v1/servers/self/up"
       mp_results.append(get(mp_path))
       print mp_path
       print get(mp_path)
check_mgmt()
check_router(rmp_list)
check_mp(rmp_list)
print rmp_list
print router_results
print mp_results

#Using fabric to run the curl commands local to each rmp
#from fabric.api import settings, run, env

#user = 'root'
#password = 'AuthApigee!'
env.hosts = ['15.184.35.217','15.184.35.226','15.184.35.236'] 

def local_router_check():
    return run('curl -ik http://localhost:8081/v1/servers/self/up')

#def local_mp_check():
#    run('curl -ik http://localhost:8082/v1/servers/self/up')

#local_router_check()
#local_mp_check()
