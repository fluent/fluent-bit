'''
 /* Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
'''

# _*_
from django.shortcuts import render, render_to_response
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseNotFound
import json
import socket
import os

# Create your views here.


avaliable_list = [
    {'ID': 'timer', 'Version': '1.0'}, 
    {'ID': 'connection', 'Version': '1.0'}, 
    {'ID': 'event_publisher', 'Version': '3.0'}, 
    {'ID': 'event_subscriber', 'Version': '1.0'}, 
    {'ID': 'request_handler', 'Version': '1.0'}, 
    {'ID': 'sensor', 'Version': '1.0'}, 
    {'ID': 'ui_app', 'Version': '1.0'}
]

# Help
def help(req):
# return "Help" page 
    return render(req, "help.html")

# View
def index(req):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    host = '127.0.0.1'
    port = 8889
    msg = ""
    err = ""

    try:
        s.connect((host, port))
        s.send(bytes("query:all", encoding='utf8'))
        s.settimeout(10)
        msg = s.recv(1024)
    except socket.timeout as e:
        err = "empty"
        print("no client connected")
    except socket.error as e:
        err = "refused"
        print("server not started")

    s.close()

    device_list = []
    if msg != "":
        devices = msg.decode('utf-8').split("*")
        for dev in devices:
            dev_info = eval(dev)
            addr = dev_info['addr']
            port = dev_info['port']
            apps = dev_info['num']
            device_list.append({'IP': addr, 'Port': port, 'apps': apps})    
    else:
        if err == "refused":
            return render(req, "empty.html")

    dlist = device_list

    return render(req, 'mysite.html', {'dlist': json.dumps(dlist)})


def apps(req):
    open_status = ''
    search_node = []
    if req.method == "POST":
            dev_search = req.POST['mykey']
            dev_addr = req.POST['voip']
            dev_port = req.POST['voport']
            open_status = 'open'
            for i in avaliable_list:
                if i['ID'] == dev_search:
                    search_node = [{'ID':dev_search, 'Version': '1.0'}]
                    print("search_node:",search_node)
                    break
                else:
                    search_node = ["Nothing find"]
                    print( "final:",search_node)
    else:
        dev_addr = req.GET['ip']
        dev_port = req.GET['port']
        open_status = 'close'

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '127.0.0.1'
    port = 8889
    msg = ""
    err = ""    

    try:
        s.connect((host, port))
        s.send(bytes("query:"+dev_addr+":"+str(dev_port), encoding='utf8'))
        msg = s.recv(1024)
    except socket.error as e:
        print("unable to connect to server")
        msg = b"fail"
    s.close()

    app_list = []

    if msg != "":
        if msg.decode() == "fail":
            return render(req, "empty.html")
        else:
            dic = eval(msg.decode(encoding='utf8'))
            app_num = dic["num"]
            for i in range(app_num):
                app_list.append(
                    {'pname': dic["applet"+str(i+1)], 'status': 'Installed', 'current_version': '1.0'})

    alist = app_list
    device_info = []
    device_info.append(
        {'IP': dev_addr, 'Port': str(dev_port), 'apps': app_num})

    print(device_info)
    return render(req, 'application.html', {'alist': json.dumps(alist), 'dlist': json.dumps(device_info), 'llist': json.dumps(avaliable_list),
    "open_status":json.dumps(open_status),"search_node": json.dumps(search_node),})


def appDownload(req):
    dev_addr = req.GET['ip']
    dev_port = req.GET['port']
    app_name = req.GET['name']

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    host = '127.0.0.1'
    port = 8889
    msg = ""

    app_path = os.path.abspath(os.path.join(os.getcwd(), "static", "upload"))
    if app_path[-1] != '/':
        app_path += '/'

    try:
        s.connect((host, port))
        s.send(bytes("install:"+dev_addr+":"+str(dev_port)+":"+app_name +
                     ":"+app_path + app_name + ".wasm", encoding='utf8'))
        msg = s.recv(1024)
    except socket.error as e:
        print("unable to connect to server")
    s.close()

    success = "ok"
    fail = "Fail!"
    status = [success, fail]
    print(msg)
    if msg == b"fail":
        return HttpResponse(json.dumps({
            "status": fail
        }))
    elif msg == b"success":
        return HttpResponse(json.dumps({
            "status": success
        }))
    else:
        return HttpResponse(json.dumps({
            "status": eval(msg.decode())["error message"].split(':')[1]
        }))


def appDelete(req):
    dev_addr = req.GET['ip']
    dev_port = req.GET['port']
    app_name = req.GET['name']

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    host = '127.0.0.1'
    port = 8889
    s.connect((host, port))
    s.send(bytes("uninstall:"+dev_addr+":" +
                 str(dev_port)+":"+app_name, encoding='utf8'))
    msg = s.recv(1024)
    s.close()
    r = HttpResponse("ok")
    return r

static_list = [{'ID': 'timer', 'Version': '1.0'}, {'ID': 'connection', 'Version': '1.0'}, {'ID': 'event_publisher', 'Version': '3.0'}, {
         'ID': 'event_subscriber', 'Version': '1.0'}, {'ID': 'reuqest_handler', 'Version': '1.0'}, {'ID': 'sensor', 'Version': '1.0'}, {'ID': 'ui_app', 'Version': '1.0'}]

def store(req):

    store_path = os.path.join('static', 'upload')
    status = []

    print(user_file_list)
    return render(req, 'appstore.html', {'staticlist': json.dumps(static_list), 'flist': json.dumps(user_file_list),'ulist':json.dumps(status)})

user_file_list = []
files_list = []
def uploadapps(req):
    status = []
    local_list = ['timer','connection','event_publisher','event_subscriber','reuqest_handler','sensor']
    req.encoding = 'utf-8'
    if req.method == 'POST':
        myfile = req.FILES.get("myfile", None)
        obj = req.FILES.get('myfile')
        store_path = os.path.join('static', 'upload')
        file_path = os.path.join('static', 'upload', obj.name)

        if not os.path.exists(store_path):
            os.makedirs(store_path)
        
        file_name = obj.name.split(".")[0]
        file_prefix = obj.name.split(".")[-1]


        if file_prefix != "wasm":
            status = ["Not a wasm file"]
        elif file_name in local_list:
            status = ["This App is preloaded"]   
        elif file_name in files_list:
            status = ["This App is already uploaded"]        
        else:
            status = []
            avaliable_list.append({'ID': file_name, 'Version': '1.0'})
            user_file_list.append({'ID': file_name, 'Version': '1.0'})
            files_list.append(file_name)   
       
        print(user_file_list)
        f = open(file_path, 'wb')
        for chunk in obj.chunks():
            f.write(chunk)
        f.close()
        return render(req, 'appstore.html', {'staticlist': json.dumps(static_list), 'flist': json.dumps(user_file_list),'ulist':json.dumps(status)})

appname_list = []

def addapps(request):
    types = ''
    print("enter addapps")
    request.encoding = 'utf-8'
    app_dic = {'ID': '', 'Version': ''}

    # if request.method == 'get':
    if "NAME" in request.GET:
        a_name = request.GET['NAME']
        if a_name != "" and a_name not in appname_list:
            appname_list.append(a_name)
            message = request.GET['NAME'] + request.GET['Version']
            app_dic['ID'] = request.GET['NAME']
            app_dic['Version'] = request.GET['Version']
            avaliable_list.append(app_dic)
        else:
            types = "Exist"
    print(avaliable_list)
    return render(request, 'appstore.html', {'alist': json.dumps(avaliable_list)})

def removeapps(req):
    app_name = req.GET['name']
    app_version = req.GET['version']
    remove_app = {'ID': app_name, 'Version': app_version}
    avaliable_list.remove(remove_app)
    user_file_list.remove(remove_app)
    files_list.remove(app_name)
    return render(req, 'appstore.html', {'alist': json.dumps(avaliable_list),'flist': json.dumps(user_file_list)})

# Test
# if __name__ == "__main__":
#    print(device_list[0]['IP'])
#    print(device['IP'])
