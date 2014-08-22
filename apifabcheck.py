from fabric.api import settings, run, env

user = 'root'
password = 'AuthApigee!'

#Using fabric to run the curl commands local to each rmp

env.hosts = ['10.22.122.11','10.22.122.12','10.22.122.13']

def local_router_check():
    run('curl -ik http://localhost:8081/v1/servers/self/up')

def local_mp_check():
    run('curl -ik http://localhost:8082/v1/servers/self/up')

local_router_check(env.hosts)
local_mp_check(env.hosts)
