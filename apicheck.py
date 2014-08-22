# Script to monitor Apigee RMP nodes

from requests import get

mgmt_port = 8080
router_port = 8081
mp_port = 8082

mgmt_ip = "15.184.35.241"
mgmt_result = ""
rmp_list = ["15.184.35.236","15.184.35.226","15.184.35.217"]
rmp_results = []

def check_mgmt():
   mgmt_path = "http://" + mgmt_ip + ":8080/v1/servers/self/up"
   mgmt_result = get(mgmt_path)
   print mgmt_path
   print mgmt_result

def check_router(rmp_list):
   i = 0
   for node in rmp_list:
       router_path = "http://" + rmp_list[i] + ":8081/v1/servers/self/up"
       print router_path
       rmp_results.append(get(router_path))
       print rmp_results[i]
       i = i + 1 

def check_mp(rmp_list):
   i = 0 
   for node in rmp_list:
       mp_path = "http://" + rmp_list[i] + ":8082/v1/servers/self/up"
       rmp_results.append(get(mp_path))
       print mp_path
       print rmp_results[i]
       i = i + 1
check_mgmt()
check_router(rmp_list)
check_mp(rmp_list)
print rmp_list
print rmp_results
