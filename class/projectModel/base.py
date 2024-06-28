#coding: utf-8
import json
import os.path
from typing import Union

import public,re
import hashlib

class projectBase:

    def check_port(self, port):
        '''
        @name 检查端口是否被占用
        @args port:端口号
        @return: 被占用返回True，否则返回False
        @author: lkq 2021-08-28
        '''
        a = public.ExecShell("netstat -nltp|awk '{print $4}'")
        if a[0]:
            if re.search(':' + port + '\n', a[0]):
                return True
            else:
                return False
        else:
            return False

    def is_domain(self, domain):
        '''
        @name 验证域名合法性
        @args domain:域名
        @return: 合法返回True，否则返回False
        @author: lkq 2021-08-28
        '''
        import re
        domain_regex = re.compile(r'(?:[A-Z0-9_](?:[A-Z0-9-_]{0,247}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,}(?<!-))\Z', re.IGNORECASE)
        return True if domain_regex.match(domain) else False


    def generate_random_port(self):
        '''
        @name 生成随机端口
        @args
        @return: 端口号
        @author: lkq 2021-08-28
        '''
        import random
        port = str(random.randint(5000, 10000))
        while True:
            if not self.check_port(port): break
            port = str(random.randint(5000, 10000))
        return port

    def IsOpen(self, port):
        '''
        @name 检查端口是否被占用
        @args port:端口号
        @return: 被占用返回True，否则返回False
        @author: lkq 2021-08-28
        '''
        ip = '0.0.0.0'
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, int(port)))
            s.shutdown(2)
            return True
        except:
            return False
    
    # 判断域名是否有效，并返回
    @staticmethod
    def check_domain(domain: str) -> Union[str, bool]:
        from panelSite import panelSite

        domain = panelSite().ToPunycode(domain).lower()

        # 判断通配符域名格式
        if domain.find('*') != -1 and domain.find('*.') == -1:
            return False

        # 判断域名格式
        reg = "^([\w\-\*]{1,100}\.){1,24}([\w\-]{1,24}|[\w\-]{1,24}\.[\w\-]{1,24})$"
        if not re.match(reg, domain):
            return False
        return domain

    def advance_check_port(self, get):
        """预先检查端口是否合格
        @author baozi <202-02-22>
        @param: 
            port  ( str ):  端口号 
        @return
        """
        port = getattr(get, "port", "")
        try:
            port = int(port)
            if 0 < port < 65535:
                data = public.ExecShell("ss  -nultp|grep ':%s '" % port)[0]
                if data:
                    msg = public.returnMsg(False, "请注意：该端口已经被占用")
                else:
                    msg = public.returnMsg(True, "验证成功")
            else:
                msg = public.returnMsg(False, "请输入正确的端口范围 1 < 端口 < 65535")
        except ValueError:
            msg = public.returnMsg(False, "请注意：该端口号为整数")

        return msg

    @staticmethod
    def _check_webserver():
        setup_path = public.GetConfigValue('setup_path')
        ng_path = setup_path + '/nginx/sbin/nginx'
        ap_path = setup_path + '/apache/bin/apachectl'
        op_path = '/usr/local/lsws/bin/lswsctrl'
        not_server = False
        if not os.path.exists(ng_path) and not os.path.exists(ap_path) and not os.path.exists(op_path):
            not_server = True
        if not not_server:
            return
        tasks = public.M('tasks').where("status!=? AND type!=?", ('1','download')).field('id,name').select()
        for task in tasks:
            name = task["name"].lower()
            if name.find("openlitespeed") != -1:
                return "正在安装OpenLiteSpeed服务，请等待安装完成后再操作"
            if name.find("nginx") != -1:
                return "正在安装Nginx服务，请等待安装完成后再操作"
            if name.lower().find("apache") != -1:
                return "正在安装Apache服务，请等待安装完成后再操作"

        return "未安装任意Web服务，请安装Nginx或Apache后再操作"
    
    def _release_firewall(self, get):
        """尝试放行端口
        @author baozi <202-04-18>
        @param: 
            get  ( dict_obj ):  创建项目的请求 
        @return 
        """

        from safeModel.firewallModel import main as firewall
        
        release = getattr(get, "release_firewall", None)
        if release in ("0", '', None, False, 0):
            return False, "注意：端口未在防火墙放行，仅可本地访问"
        port = getattr(get, "port", None)
        project_name = getattr(get, "name", "") or getattr(get, "pjname", "") or getattr(get, "project_name", "")
        if port is None:
            return True, ""

        new_get = public.dict_obj()
        new_get.protocol = "tcp"
        new_get.ports = str(port)
        new_get.choose = "all"
        new_get.address = ""
        new_get.domain = ""
        new_get.types = "accept"
        new_get.brief = "网站项目：" + project_name + "放行的端口"
        new_get.source = ""
        try:
            firewall_obj = firewall()
            get_obj = public.dict_obj()
            get_obj.p = 1
            get_obj.limit = 99
            get_obj.query = str(port)
            res_data = firewall_obj.get_rules_list(get_obj)  # 查询是否已经有端口

            if len(res_data) == 0:
                res = firewall_obj.create_rules(new_get)
            for i in res_data:
                new_get.id = i.get("id")
                res = firewall_obj.modify_rules(new_get)
  
            if res["status"]:
                return True, ""
            else:
                return False, "注意：端口在防火墙放行操作失败，仅可本地访问"
        except:
            return False, "注意：端口在防火墙放行操作失败，仅可本地访问"


class ProcessTask:
    _cache_path = "{}/data/process_cache.json".format(public.get_panel_path())

    def __init__(self, model: str, func: str, args: dict, ignore_check: bool = False):
        self.task_id = hashlib.md5((model + func + json.dumps(args)).encode()).hexdigest()
        self.model = model
        self.func = func
        self.args = args
        if ignore_check:
            self._remove_cache()

    def _check_exists(self) -> bool:
        if os.path.exists(self._cache_path):
            try:
                data: list = json.loads(public.readFile(self._cache_path))
            except:
                data = []
            if self.task_id not in data:
                data.append(self.task_id)
                public.writeFile(self._cache_path, json.dumps(data))
                return False
            else:
                return True
        data = [self.task_id, ]
        public.writeFile(self._cache_path, json.dumps(data))
        return False

    def _remove_cache(self) -> None:
        if os.path.exists(self._cache_path):
            data: list = json.loads(public.readFile(self._cache_path))
            if self.task_id in data:
                data.remove(self.task_id)
                public.writeFile(self._cache_path, json.dumps(data))

    def _run(self) -> None:
        from importlib import import_module
        module = import_module(".{}".format(self.model), package="projectModel")
        main_class = getattr(module, "main", None)
        if main_class:
            func = getattr(main_class(), self.func, None)
            if func is not None and callable(func):
                func(self.args)
                self._remove_cache()

    def run(self) -> Union[bool, int]:
        from multiprocessing import Process
        if self._check_exists():
            return False
        p = Process(target=self._run, daemon=True)
        p.start()
        return p.pid
