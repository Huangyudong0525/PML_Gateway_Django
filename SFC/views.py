from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
import http.client
from multiprocessing import Process
import subprocess
import os
import sys
import time
import signal
import psutil
import json
import paramiko

processes = dict()

#解决sudo权限
#sudopw = "123"
#cmd = " "
#os.system("echo %s |sudo -S %s"%(sudopw, cmd))

def index(request):
    return render(request, "index.html",)

def killProc(pid):
    baseProc = psutil.Process(pid)   #读取进程
    childrenProcList = baseProc.children(recursive=True)  #递归读取进程的子进程树
    for proc in childrenProcList:
        os.system('sudo kill -2 %d'%proc.pid)
        #os.kill(proc.pid, signal.SIGINT)    #杀死子进程
        # if (len(proc.children(recursive=True)) == 0):
        # os.kill(pid, signal.SIGINT)
        # else:
        # killProc(proc.pid)

def choose_nf(nf_name, service_id, nexthop_id):
    cmd1 = "cd /home/hyd/openNetVM/examples/%s ; sudo ./go.sh %s -d %s " % (nf_name, service_id, nexthop_id)
    devnull = open('/dev/null', 'w')
    p = subprocess.Popen(cmd1, stdout=devnull, shell=True)
    print("nf ok")
    return p.pid

def choose_nf_router(service_id):
    cmd1 = "cd /home/hyd/openNetVM/examples/nf_router ; sudo ./go.sh %s -f ./route.conf " % (service_id)
    devnull = open('/dev/null', 'w')
    p = subprocess.Popen(cmd1, stdout=devnull, shell=True)
    print("nf_router ok")
    return p.pid

def choose_firewall(service_id, nexthop_id):
    cmd1 = "cd /home/hyd/openNetVM/examples/firewall ; sudo ./go.sh %s -d %s -f ./rules.json " % (service_id, nexthop_id)
    devnull = open('/dev/null', 'w')
    p = subprocess.Popen(cmd1, stdout=devnull, shell=True)
    print("firewall ok")
    return p.pid

def choose_bridge(service_id):
    cmd1 = "cd /home/hyd/openNetVM/examples/bridge ; sudo ./go.sh %s " % (service_id)
    devnull = open('/dev/null', 'w')
    p = subprocess.Popen(cmd1, stdout=devnull, shell=True)
    print("bridge ok")
    return p.pid

# def start_nf_router(service_id):
#     pid = choose_nf_router(service_id)
#     processes[service_id] = pid
#
# def start_firewall(service_id, nexthop_id):
#     pid = choose_firewall(service_id, nexthop_id)
#     processes[service_id] = pid
#
# def start_bridge(service_id):
#     pid = choose_bridge(service_id)
#     processes[service_id] = pid

def start_nf_router(request):
    service_id = request.POST.get('service_id')
    result = {"Result": "success", "Message": "创建路由器成功"}
    result['id']=service_id
    pid = choose_nf_router(service_id)
    processes[service_id] = pid
    # response = HttpResponse(json.dumps(result, ensure_ascii=False), content_type="application/json,charset=utf-8")
    # response["Access-Control-Allow-Origin"]="*" #所有ip均可访问
    return JsonResponse(result)

def start_firewall(request):
    service_id = request.POST.get('service_id')
    nexthop_id = request.POST.get('nexthop_id')
    pid = choose_firewall(service_id, nexthop_id)
    processes[service_id] = pid
    result = {"Result": "success", "Message": "创建防火墙成功"}
    result['id'] = service_id
    return JsonResponse(result)

def start_bridge(request):
    service_id = request.POST.get('service_id')
    result = {"Result": "success", "Message": "创建桥成功"}
    result['id']=service_id
    pid = choose_bridge(service_id)
    processes[service_id] = pid
    return JsonResponse(result)

def stop_nf(request):
    service_id = request.POST.get('service_id')
    pid = processes[service_id]
    killProc(pid)
    result = {"Result": "success", "Message": "删除网络功能成功"}
    result['id'] = service_id
    return JsonResponse(result)

def read_nf_router_conf(request):
    rules_list1 = []
    rules_list2 = []
    rules_list3 = []
    rules_container = []
    #with open('/home/hyd/openNetVM/examples/nf_router/route.conf', "r", encoding='utf-8') as fid:
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', "r", encoding='utf-8') as fid:
        for line in fid.readlines()[1:]:    #将文件按行读取为列表
            num = line.split(' ')           #每行用空格分隔为两部分，分别用列表存
            rules_list1.append(num[0])
            rules_list2.append(num[1])
    rules_list3 = [x.strip() for x in rules_list2 if x.strip() != '']   #删除列表中的换行符
    for k in range(len(rules_list1)):
        rules_dict = dict()                 #将列表值存入字典
        rules_dict['dst_ip'] = rules_list1[k]
        rules_dict['to_service_Id'] = rules_list3[k]
        rules_container.append(rules_dict)       #将字典装入列表
    #     rules_dict[rules_list1[k]] = rules_list3[k]
    # rules_dict1 = json.dumps(rules_dict)
    response = JsonResponse(rules_container, safe = False)
    return response

def read_firewall_conf(request):
    rules_container = []
    with open('/home/hyd/openNetVM/examples/firewall/rules.json', "r", encoding='utf-8') as fid:
    #with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/rules.json', "r", encoding='utf-8') as fid:
        rules_dict = json.load(fid)    #将json文件读取并转换为字典
    key_list =list(rules_dict.keys())     #将字典的key值存进列表
    for key in range(len(key_list)):
        rules_dict1 = {}                   #创建新的字典用于存列表装字典格式
        rules_dict1['rule_name'] = key_list[key]
        rules_dict1['src_ip'] = rules_dict[key_list[key]]['ip']
        rules_dict1['depth'] = rules_dict[key_list[key]]['depth']
        rules_dict1['action'] = str(rules_dict[key_list[key]]['action'])
        rules_container.append(rules_dict1)        #将字典装进列表
    return JsonResponse(rules_container, safe = False)


def nf_router_conf(request):
    rules_list1 = []
    rules_list2 = []
    rules_list3 = []
    dst_ip = request.POST.get('dst_ip')
    to_service_Id = request.POST.get('to_service_Id')
    # with open('/home/hyd/openNetVM/examples/nf_router/route.conf', "a", encoding='utf-8') as fid:
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', 'a', encoding='utf-8') as fid:
        fid.write('%s %s\n'%(dst_ip, to_service_Id))
    # with open('/home/hyd/openNetVM/examples/nf_router/route.conf', "r", encoding='utf-8') as fid:
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', "r", encoding='utf-8') as fid:
        for line in fid.readlines():  # 将文件按行读取为列表
            num = line.split(' ')  # 每行用空格分隔为两部分，分别用列表存
            rules_list1.append(num[0])
            rules_list2.append(num[1])
    rules_list3 = [x.strip() for x in rules_list2 if x.strip() != '']  # 删除列表中的换行符
    rules_list3[0] = int(rules_list3[0])+1
    # with open('/home/hyd/openNetVM/examples/nf_router/route.conf', "w", encoding='utf-8') as fid:
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', "w", encoding='utf-8') as fid:
        for k in range(len(rules_list1)):
            fid.write('%s %s\n'%(rules_list1[k], rules_list3[k]))
    # with open('/home/hyd/openNetVM/examples/nf_router/route.conf', "r", encoding='utf-8') as fid:
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', 'r', encoding='utf-8') as fid:
        rules_list = fid.readlines()[1:]
    result = {"Result": "success", "Message": "添加路由规则成功"}
    result["data"] = rules_list
    return JsonResponse(result)

def del_nf_router_conf(request):
    rules_list1 = []
    rules_list2 = []
    rules_list3 = []
    dst_ip = request.POST.get('dst_ip')
    #with open('/home/hyd/openNetVM/examples/nf_router/route.conf', 'r', encoding='utf-8') as fid:
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', 'r', encoding='utf-8') as fid:
        rules_list = fid.readlines()
    #with open('/home/hyd/openNetVM/examples/nf_router/route.conf', 'w', encoding='utf-8') as fid:
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', 'w', encoding='utf-8') as fid:
        for line in rules_list:
            if dst_ip in line:
                del line
            else:
                fid.write(line)
    # with open('/home/hyd/openNetVM/examples/nf_router/route.conf', 'r', encoding='utf-8') as fid:
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', "r", encoding='utf-8') as fid:
        for line in fid.readlines():  # 将文件按行读取为列表
            num = line.split(' ')  # 每行用空格分隔为两部分，分别用列表存
            rules_list1.append(num[0])
            rules_list2.append(num[1])
    rules_list3 = [x.strip() for x in rules_list2 if x.strip() != '']  # 删除列表中的换行符
    rules_list3[0] = int(rules_list3[0])-1
    # with open('/home/hyd/openNetVM/examples/nf_router/route.conf', 'w', encoding='utf-8') as fid:
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', "w", encoding='utf-8') as fid:
        for k in range(len(rules_list1)):
            fid.write('%s %s\n'%(rules_list1[k], rules_list3[k]))
    result = {"Result": "success", "Message": "删除路由规则成功"}
    #with open('/home/hyd/openNetVM/examples/nf_router/route.conf', 'r', encoding='utf-8') as fid:
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', 'r', encoding='utf-8') as fid:
        rules_list = fid.readlines()
    result['data'] = rules_list
    return JsonResponse(result)


def firewall_conf(request):
    rule_name = request.POST.get('rule_name')
    src_ip = request.POST.get('src_ip')
    depth = request.POST.get('depth')
    action = int(request.POST.get('action'))
    with open('/home/hyd/openNetVM/examples/firewall/rules.json', 'r') as fid:
    #with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/rules.json', 'r', encoding='utf-8') as fid:
        rules_dict = json.load(fid)
    rules_dict[rule_name] = {}
    rules_dict[rule_name]['ip'] = src_ip
    rules_dict[rule_name]['depth'] = depth
    rules_dict[rule_name]['action'] = action
    with open('/home/hyd/openNetVM/examples/firewall/rules.json', "w") as fid:
    #with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/rules.json', "w", encoding='utf-8') as fid:
        json.dump(rules_dict, fid)
    result = {"Result": "success", "Message": "添加防火墙规则成功"}
    result["data"] = rules_dict
    return JsonResponse(result)

def del_firewall_conf(request):
    rule_name = request.POST.get('rule_name')
    with open('/home/hyd/openNetVM/examples/firewall/rules.json', 'r') as fid:
    #with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/rules.json', "r") as fid:
        rules_dict = json.load(fid)
    del rules_dict[rule_name]
    with open('/home/hyd/openNetVM/examples/firewall/rules.json', "w") as fid:
    #with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/rules.json', "w") as fid:
        json.dump(rules_dict, fid)
    result = {"Result": "success", "Message": "删除防火墙规则成功"}
    result["data"] = rules_dict
    return JsonResponse(result)



# if __name__ == '__main__':
#
#     linux_pid = None
#     while True:
#         fd = sys.stdin.fileno()
#         old_settings = termios.tcgetattr(fd)
#         # old_settings[3]= old_settings[3] & ~termios.ICANON & ~termios.ECHO
#         try:
#             tty.setraw(fd)
#             ch = sys.stdin.read(1)
#         finally:
#             termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
#         if ch == 'o':
#             pid = int(raw_input('please input pid you want to create: '))
#             start_nf_router(pid)
#         if ch == 'i':
#             pid = int(raw_input('please input pid you want to kill: '))
#             stop_nf(pid)
#         if ch == 'e':
#             os._exit(0)

# 配置ACL
def set_acl(request):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    acl_name = request.POST.get('acl_name')
    rule = request.POST.get('rule')
    ssh.connect(hostname = '172.171.15.41', port = 22, username = 'pml', password = '123')
    chan = ssh.invoke_shell()
    chan.send('system-view \n' )
    if rule == "any":
        chan.send( "acl %s \n" % acl_name)
        chan.send("rule permit any \n")
    else:
        ip = request.POST.get('ip')
        mask = request.POST.get('mask')
        chan.send("acl %s \n" % acl_name)
        chan.send( "rule permit ip source %s %s \n"%(ip, mask))
    chan.send('quit \n')
    result = {"Result":"success", "Message":"添加ACL成功"}
    return HttpResponse(result)

# 删除ACL
def del_acl(request):
    acl_name = request.POST.get('acl_name')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname='172.171.15.41', port=22, username='pml', password='123')
    chan = ssh.invoke_shell()
    chan.send('system-view \n')
    chan.send("undo acl %s \n" % acl_name)
    chan.send('quit \n')
    result = {"Result": "success", "Message": "删除ACL成功"}
    return HttpResponse(result)

# 配置流分类
def set_classofier(request):
    in_port = request.POST.get('in_port')
    acl_name = request.POST.get('acl_name')
    out_port = request.POST.get('out_port')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname='172.171.15.41', port=22, username='pml', password='123')
    chan = ssh.invoke_shell()
    chan.send('system-view \n')
    chan.send( "interface gigabitethernet %s \n" % in_port)
    chan.send( "traffic-redirect inbound acl %s interface gigabitethernet %s \n"%(acl_name, out_port))
    chan.send('quit \n')
    result = {"Result": "success", "Message": "添加流分类成功"}
    return HttpResponse(result)

# 删除流分类
def del_classifier(request):
    in_port = request.POST.get('in_port')
    acl_name = request.POST.get('acl_name')
    out_port = request.POST.get('out_port')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname='172.171.15.41', port=22, username='pml', password='123')
    chan = ssh.invoke_shell()
    chan.send('system-view \n')
    chan.send("interface gigabitethernet %s \n" % in_port)
    chan.send("undo traffic-redirect inbound acl %s interface gigabitethernet %s \n" % (acl_name, out_port))
    chan.send('quit \n')
    result = {"Result": "success", "Message": "删除流分类成功"}
    return HttpResponse(result)










