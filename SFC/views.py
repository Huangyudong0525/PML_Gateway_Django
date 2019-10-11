from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
import http.client
# Create your views here.
from multiprocessing import Process
import subprocess
import os
import sys
import time
import signal
import psutil
import json

processes = dict()

def index(request):
    return render(request, "index.html",)

def killProc(pid):
    baseProc = psutil.Process(pid)
    childrenProcList = baseProc.children(recursive=True)
    for proc in childrenProcList:
        os.kill(proc.pid, signal.SIGINT)
        # if (len(proc.children(recursive=True)) == 0):
        # os.kill(pid, signal.SIGINT)
        # else:
        # killProc(proc.pid)

def choose_nf(nf_name, service_id, nexthop_id):
    cmd1 = "cd /home/hyd/openNetVM/examples/%s ; ./go.sh %d -d %d " % (nf_name, service_id, nexthop_id)
    devnull = open('/dev/null', 'w')
    p = subprocess.Popen(cmd1, stdout=devnull, shell=True)
    print("nf ok")
    return p.pid

def choose_nf_router(service_id):
    cmd1 = "cd /home/hyd/openNetVM/examples/nf_router ; ./go.sh %d  -f ./route.conf " % (service_id)
    devnull = open('/dev/null', 'w')
    p = subprocess.Popen(cmd1, stdout=devnull, shell=True)
    print("nf_router ok")
    return p.pid

def choose_firewall(service_id, nexthop_id):
    cmd1 = "cd /home/hyd/openNetVM/examples/firewall ; ./go.sh %d -d %d -f ./rules.json " % (service_id, nexthop_id)
    devnull = open('/dev/null', 'w')
    p = subprocess.Popen(cmd1, stdout=devnull, shell=True)
    print("firewall ok")
    return p.pid

def choose_bridge(service_id):
    cmd1 = "cd /home/hyd/openNetVM/examples/bridge ; ./go.sh %d " % (service_id)
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
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', "r", encoding='utf-8') as fid:
        for line in fid.readlines()[1:]:
            num = line.split(' ')
            rules_list1.append(num[0])
            rules_list2.append(num[1])
    rules_list3 = [x.strip() for x in rules_list2 if x.strip() != '']
    for k in range(len(rules_list1)):
        rules_dict = dict()
        rules_dict['dst_ip'] = rules_list1[k]
        rules_dict['to_service_Id'] = rules_list3[k]
        rules_json = json.dumps(rules_dict)
        rules_container.append(rules_json)
    #     rules_dict[rules_list1[k]] = rules_list3[k]
    # rules_dict1 = json.dumps(rules_dict)
    return HttpResponse(rules_container)

def read_firewall_conf(request):
    rules_container = []
    rules_dict2 = {}
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/rules.json', "r", encoding='utf-8') as fid:
        rules_dict = json.load(fid)
    # rules_dict1 = json.dumps(rules_dict)
    #
    # rules_dict2['rule_name'] = rules_dict1[k]
    return HttpResponse(rules_dict)


def nf_router_conf(request):
    dst_ip = request.POST.get('dst_ip')
    to_service_Id = request.POST.get('to_service_Id')
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', 'a', encoding='utf-8') as fid:
        fid.write('%s %s\n'%(dst_ip, to_service_Id))
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', 'r', encoding='utf-8') as fid:
    # with open('/home/hyd/openNetVM/examples/nf_router/router.conf', 'w') as fid:
        rules_list = fid.readlines()[1:]
    result = {"Result": "success", "Message": "添加路由规则成功"}
    result["data"] = rules_list
    return JsonResponse(result)

def del_nf_router_conf(request):
    dst_ip = request.POST.get('dst_ip')
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', 'r', encoding='utf-8') as fid:
    # with open('/home/hyd/openNetVM/examples/nf_router/router.conf', 'w') as fid:
        rules_list = fid.readlines()
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', 'w', encoding='utf-8') as fid:
        for line in rules_list:
            if dst_ip in line:
                del line
            else:
                fid.write(line)
    result = {"Result": "success", "Message": "删除路由规则成功"}
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/route.conf', 'r', encoding='utf-8') as fid:
        rules_list = fid.readlines()
    result['data'] = rules_list
    return JsonResponse(result)


def firewall_conf(request):
    rule_name = request.POST.get('rule_name')
    src_ip = request.POST.get('src_ip')
    depth = request.POST.get('depth')
    action = request.POST.get('action')
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/rules.json', 'r', encoding='utf-8') as fid:
    #with open('/home/hyd/openNetVM/examples/firewall/rules.json', 'r') as fid:
        rules_dict = json.load(fid)
    rules_dict[rule_name] = {}
    rules_dict[rule_name]['ip'] = src_ip
    rules_dict[rule_name]['depth'] = depth
    rules_dict[rule_name]['action'] = action
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/rules.json', "w", encoding='utf-8') as fid:
    # with open('/home/hyd/openNetVM/examples/firewall/rules.json', "w") as fid:
        json.dump(rules_dict, fid)
    result = {"Result": "success", "Message": "添加防火墙规则成功"}
    result["data"] = rules_dict
    return JsonResponse(result)

def del_firewall_conf(request):
    rule_name = request.POST.get('rule_name')
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/rules.json', "r") as fid:
        rules_dict = json.load(fid)
    del rules_dict[rule_name]
    with open('C:/Users/HYD/PycharmProjects/PML_Security_Gateway/SFC/rules.json', "w") as fid:
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




