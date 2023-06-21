import subprocess
import requests
import os
import lief
import lzma
import subprocess

from ppadb.client import Client


target = "<ENTER APP NAME HERE>"
 
def proc_version():
    adb = Client(host='127.0.0.1',port=5037)
    devices = adb.devices()
    mydevice = devices[0]
    proc_version = mydevice.shell('getprop ro.product.cpu.abi')
    return proc_version

def frida_gadget_latest():
    r = requests.get('https://github.com/frida/frida/releases/latest', allow_redirects=False)
    redirect_url = (r.headers['Location'])
    latest_version = (redirect_url.split('/')[-1])
    return latest_version

def pull_apk(app_name):
    adb = Client(host='127.0.0.1',port=5037)
    devices = adb.devices()
    mydevice = devices[0]
    long_name = mydevice.shell('pm list packages | grep ' + app_name).replace('package:','')
    path = mydevice.shell('pm path ' + long_name).replace('package:','')
    mydevice.shell('mkdir /sdcard/data/')
    command = 'cp '+' '.join(path.split())+' /sdcard/data/'
    mydevice.shell(command)
    mydevice.pull('/sdcard/data/base.apk','base.apk')
    mydevice.shell('rm -r /sdcard/data/')

def check_for_so():
    so_file = False
    path = os.getcwd()
    decode_apk()
    ext_path = "\\base\\lib\\"
    for files in os.listdir(path+ext_path):
        if any(File.endswith(".so") for File in os.listdir(path+ext_path+files)):
               so_file = True
    return so_file

def manifest(app_name):
    adb = Client(host='127.0.0.1',port=5037)
    devices = adb.devices()
    mydevice = devices[0]
    activity = mydevice.shell('dumpsys package | grep ' + app_name + '| grep Activity').strip().split("/",1)[1]
    if "main" in activity.lower():
        Main = True
        print ("Target is: " + activity)
    else:
        Main = False
    return Main, activity

def decode_apk():
    path = os.getcwd()
    apk_tool_decode= subprocess.Popen((path+"\\apktool.bat", "d", "base.apk","-f"),stdout=subprocess.PIPE).stdout
    for line in apk_tool_decode:
        print(line.decode('utf-8'))
    apk_tool_decode.close()

def encode_sign_apk():
    path = os.getcwd()
    print ("Building the apk")
    apk_tool_encode= subprocess.Popen((path+"\\apktool.bat", "b", "-f","base"),stdout=subprocess.PIPE).stdout
    for line in apk_tool_encode:
        print(line.decode('utf-8'))
    apk_tool_encode.close()
    r = requests.get('https://github.com/patrickfav/uber-apk-signer/releases/latest', allow_redirects=False)
    redirect_url = (r.headers['Location'])
    latest_version = (redirect_url.split('/')[-1])
    url = "https://github.com/patrickfav/uber-apk-signer/releases/download/" + latest_version + "/uber-apk-signer-" + latest_version[1:] + ".jar"
    response = requests.get(url, stream=True)
    response.raise_for_status()
    name = 'uber-apk-signer-'+latest_version+'.jar'
    with open(name, 'wb') as handle:
        for block in response.iter_content(1024):
            handle.write(block)
    print("signing the apk")
    subprocess.call(['java', '-jar', name, '-a', path+'\\base\\dist\\'])
    print ("apk signed")

def install_apk():
    path = os.getcwd()
    adb = Client(host='127.0.0.1',port=5037)
    devices = adb.devices()
    mydevice = devices[0]
    install = mydevice.install(path+'\\base\\dist\\base-aligned-debugSigned.apk')
    return install


def line_num_for_phrase_in_file(phrase, filename):
    with open(filename,'r') as f:
        for (i, line) in enumerate(f):
            if phrase in line:
                return i
    return -1
    

path = os.getcwd()

adb_started = False
while adb_started is False:
    try:
        version = str(proc_version().strip())
        if version == "arm64-v8a":
            version = "arm64"
        if version == "armeabi-v7a":
            version = "arm"
        url = "https://github.com/frida/frida/releases/download/" + frida_gadget_latest() + "/frida-gadget-" + frida_gadget_latest() + "-android-" + version + ".so.xz"
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open('libfrida.so.xz', 'wb') as handle:
            for block in response.iter_content(1024):
                handle.write(block)
        with lzma.open(path+"\\libfrida.so.xz") as f, open('libfrida.so', 'wb') as fout:
            file_content = f.read()
            fout.write(file_content)
        pull_apk(target)
        ext_path = "\\base\\lib\\"
        check_for_so()
        if check_for_so:
            for files in os.listdir(path+ext_path):
                test = os.listdir(path+ext_path+files)
                for file in test:
                    try:
                        so_files = (path+ext_path+files+"\\"+file).strip()
                        libnative = lief.parse(so_files)
                        libnative.add_library("libfrida.so")
                        libnative.write(so_files)
                        print ("Frida injected into " + so_files)
                    except AttributeError:
                        pass
        print ("Going to try to inject into the .smali")
        result, activity = manifest(target)
        search_string = ".method constructor <init>"
        position_string = "return-void"

        if result:
            print ("Looking for smali injection point\n")
            acti_name = activity.split('.')[-1]
            for folder, dirs, files in os.walk(path+"\\base\\smali\\"):
                for file in files:
                    fullpath = os.path.join(folder, file)
                    with open(fullpath, 'r') as f:
                        for line in f:
                            if acti_name in line:
                                if (line_num_for_phrase_in_file(search_string,fullpath) != -1):
                                    fline=open(fullpath).readline().rstrip()
                                    void_linnum = (line_num_for_phrase_in_file(position_string,fullpath))
                                    print ("injection spot found...auto injecting")
                                    data = f.readlines()
                                    data[void_linnum-2]='\n    const-string v0, "frida-gadget"'
                                    data[void_linnum-1]='\n    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n\n'
                                    data[void_linnum]= '    '+position_string+'\n'
                                    data[void_linnum+1]= '.end method'
                                    with open(fullpath, 'w') as f:
                                        f.write(fline)
                                        f.writelines(data)
                                        break
            print ("Injection Completed")
            encode_sign_apk()
            if install_apk():
                print ('app installed test frida connection :-)')
            else:
                print ('install failed please try manually')
            


        
        else:
            print ("No obvious target manual checking required")
            quit()
        adb_started = True
    except IndexError:
        print ("No device Detected")
        quit()
    except:
        subprocess.call(['adb.exe', 'devices'])
        quit()
##    
        

