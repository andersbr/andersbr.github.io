from fabric.api import task, execute, settings, run, env, roles

env.roledefs = {
    'stbmgmt':['15.184.35.241'],
    'stbrmp':['15.184.35.217','15.184.35.226','15.184.35.236'],
}
env.user = 'root'
env.password = ''
env.warn_only = True

#Using fabric to run the curl commands local to each rmp


def check_all():
    router_results = execute(local_router_check)
    mp_results = execute(local_mp_check)
    return router_results
    return mp_results

@roles('stbmgmt')
def mgmt_check():
    execute(mgmt_check)
    pass
 
def local_router_check():
    return run('curl http://localhost:8081/v1/servers/self/up')

def local_mp_check():
    return run('curl http://localhost:8082/v1/servers/self/up')

def apigee_start():
    run('/opt/apigee/apigee4/bin/all-start.sh')

def apigee_stop():
    run('/opt/apigee/apigee4/bin/all-stop.sh')

@roles('stbrmp')
def apigee_restart():
    run('cd /opt/apigee/apigee4/bin && ./all-stop.sh && ./all-start.sh')
    pass
