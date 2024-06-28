# coding: utf-8
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: wuwei <bt_wuwei@qq.com>
# -------------------------------------------------------------------
import json
import os
import re
import sys
import traceback
import datetime

panelPath = "/www/server/panel"
os.chdir(panelPath)
sys.path.append("class/")
sys.path.insert(0, "/www/server/panel/class")
import public
from monitorModel.base import monitorBase
from typing import NoReturn, Dict, AnyStr, List


# ------------------------------
# 常用软件状态
# ------------------------------


class main(monitorBase):
    """
    常用软件负载情况检测
    """
    soft_introduction = {
        'nginx': "Nginx是一个高性能的HTTP和反向代理web服务器，轻量级，占有内存少，并发能力强。",
        'mysqld_safe': "MySQL是一种关系数据库管理系统。",
        'redis-server': "Redis是一个高性能的key-value数据库。",
        'mongod': "Mongod 基于分布式文件存储的数据库，旨在为WEB应用提供可扩展的高性能数据存储解决方案。",
        'postgres': "PostgreSQL 是一个免费的对象-关系数据库服务器。",
        'memcached': "Memcached 是一个高性能的分布式内存对象缓存系统。",
        'httpd': "Apache 一个安全，高效且可扩展的服务器，该服务器提供与当前HTTP标准同步的HTTP服务。",
        'pure-ftpd': "PureFTP是一款专注于程序健壮和软件安全的免费FTP服务器软件。",
        'jsvc': "Tomcat 开发和调试JSP程序的首选。",
        'dockerd': "Docker 是一个开源的应用容器引擎。",
    }
    statusOption = {"0": "stop", "1": "start", "2": "restart"}
    ROWS = 5
    sys.path.insert(0, 'class/')
    from system import system
    syst = system()

    def __init__(self):
        self.json_path = "{}/class/monitorModel/data/soft_info.json".format(panelPath)
        if os.path.exists(self.json_path) and public.readFile(self.json_path) != '':
            data = json.loads(public.readFile(self.json_path))
        else:
            data = {"mysqld_safe": {},
                    "redis-server": {},
                    "mongod": {},
                    "postgres": {},
                    "nginx": {},
                    "memcached": {},
                    "httpd": {},
                    "pure-ftpd": {},
                    "jsvc": {},
                    "dockerd": {},
                    "status": 0}
        if int(data['status']):
            if public.M('crontab').where('name=?', u'[勿删]常用软件资源监视进程').count():
                self.set_cron()
        else:
            if not public.M('crontab').where('name=?', u'[勿删]常用软件资源监视进程').count():
                self.del_cron()
        self.control_status = data['status']

    # 获取软件负载的总调度函数
    def get_status(self, get: Dict) -> Dict:
        """
        获取常用软件负载情况总调度函数
        :param get:
        :type:服务类型
        :return:
        """
        try:
            if not hasattr(get, 'type'):
                return public.returnMsg(False, '参数传递错误，请重试!')
            sql_set = {
                "mysqld_safe": self.__get_mysql_status,
                "redis-server": self.__get_redis_status,
                "mongod": self.__get_mongo_status,
                "postgres": self.__get_pgsql_status,
                "nginx": self.__get_nginx_status,
                "memcached": self.__get_memcached_status,
                "httpd": self.__get_apache_status,
                "pure-ftpd": self.__get_ftp_status,
                "jsvc": self.__get_tomcat_status,
                "dockerd": self.__get_docker_status,
                'tomcat_info': self.__get_tomcat_usr_info
            }
            if get.type == 'tomcat_info':
                return self.__get_tomcat_usr_info()
            if 'redis' in get.type:
                get.type = "redis-server"
            if 'pure' in get.type:
                get.type = "pure-ftpd"
            installation = self.__is_installation(get.type)
            if get.type not in self.__get_sever_status_list():
                return {"status": False, "soft_introduction": self.soft_introduction.get(get.type),
                        'installation': installation}
            if not int(self.control_status):
                return {"status": True, "soft_introduction": self.soft_introduction.get(get.type),
                        'installation': installation, "control_status": False}
            infos = {}
            infos['soft_info'] = sql_set.get(get.type)()
            infos["soft_introduction"] = self.soft_introduction[get.type]
            infos['status'] = True
            infos['installation'] = installation
            infos['control_status'] = self.control_status
            if get.type == 'dockerd':
                if not hasattr(get, 'limit'):
                    return public.returnMsg(False, '参数传递错误，请重试!')
                if not hasattr(get, 'p'):
                    return public.returnMsg(False, '参数传递错误，请重试!')
                self.ROWS = int(get.limit)
                public.print_log(infos['soft_info'])
                res = self.get_page(infos['soft_info']['Container'],
                                    get)
                public.print_log(res)
                infos['page'] = res['page']
                infos['soft_info']['Container'] = res['data']
            return infos
        except:
            pass

    # 软件状态调整的总调度函数
    def sever_admin(self, get: Dict) -> Dict:
        try:
            if not hasattr(get, 'option'):
                return public.returnMsg(False, '参数传递错误，请重试!')
            service = {
                'mongod': self.__mongod_admin,
                'redis-server': self.__redis_admin,
                'memcached': self.__memcached_admin,
                'dockerd': self.__docker_admin,
                'jsvc': self.__tomcat_admin,
                'pure-ftpd': self.__ftp_admin,
                'httpd': self.__apache_admin,
                'mysqld_safe': self.__mysqld_admin,
                "nginx": self.__nginx_admin,
                "postgres": self.__pgsql_admin
            }
            if 'redis' in get.name:
                get.name = "redis-server"
            if 'pure' in get.name:
                get.name = "pure-ftpd"
            installation = self.__is_installation(get.name)
            if not installation:
                return public.returnMsg(False, "该服务未安装")
            return service.get(get.name, "未找到{}服务".format(get.name))(get.option)
        except:
            return public.returnMsg(False, "设置出错")
            pass

    def __is_installation(self, name: AnyStr) -> bool:
        map = {
            "mysqld_safe": "mysqld",
            "redis-server": "redis",
            "mongod": "mongodb",
            "postgres": "pgsql",
            "nginx": "nginx",
            "memcached": "memcached",
            "httpd": "httpd",
            "pure-ftpd": "pure-ftpd",
            "jsvc": "tomcat",
            "dockerd": "docker",
            "php": "php"
        }
        import glob
        dir_path = '/etc/init.d/'
        files = [os.path.basename(f) for f in glob.glob(dir_path + "*")]
        if name == "dockerd":
            res = public.ExecShell('docker -v')[0]
            if 'version' in res:
                return True
            return False
        if name == "postgres":
            res = public.ExecShell('/www/server/pgsql/bin/psql --version')[0]
            pgsql = False
            if 'PostgreSQL' in res:
                pgsql = True
            Manager = False
            if os.path.exists('/www/server/panel/plugin/pgsql_manager'):
                Manager = True
            return {'pgsql': pgsql, 'Manager': Manager}
        if name == "php":
            php_l = [i for i in files if name in i.lower()]
            if len(php_l) != 0:
                return True
        if map[name] in files:
            return True
        return False

    def __get_nginx_status(self) -> Dict:
        """
        获取nginx负载情况
        :return:{'soft_info':soft_info,'pro_info':pro_info,'memory_info':memory_info}
        """
        try:
            nginx_info = json.loads(public.readFile(self.json_path))['nginx']
            return nginx_info
        except:
            # public.print_log(traceback.format_exc())
            return {"soft_info": "软件查询出错"}

    def __get_mysql_status(self) -> Dict:
        """
        获取MySQL数据库负载情况
        :return:{'soft_info':soft_info,'pro_info':pro_info,'memory_info':memory_info}
        """
        try:
            mysql_info = json.loads(public.readFile(self.json_path))['mysqld_safe']
            return mysql_info
        except:
            # public.print_log(traceback.format_exc())
            return {"soft_info": "软件查询出错"}

    def __get_redis_status(self) -> Dict:
        """
        获取redis的服务信息，进程信息，内存信息
        :return:{'soft_info':soft_info,'pro_info':pro_info,'memory_info':memory_info}
        """
        try:
            redis_info = json.loads(public.readFile(self.json_path))['redis-server']
            return redis_info
        except:
            # public.print_log(traceback.format_exc())
            return {"soft_info": "软件查询出错"}

    def __get_mongo_status(self) -> Dict:
        """
        获取mongo数据库负载信息
        :return:{'soft_info':soft_info,'pro_info':pro_info,'memory_info':memory_info}
        """
        try:
            mongo_info = json.loads(public.readFile(self.json_path))['mongod']
            return mongo_info
        except:
            pass
            # public.print_log(traceback.format_exc())

    def __get_pgsql_status(self) -> Dict:
        """
        获取pgsql的服务信息，进程信息，内存信息
        :return: {'soft_info':soft_info,'pro_info':pro_info,'memory_info':memory_info}
        """
        try:
            postgres_info = json.loads(public.readFile(self.json_path))['postgres']
            return postgres_info
        except:
            pass
            # public.print_log(traceback.format_exc())

    def __get_memcached_status(self) -> Dict:
        """
        获取memcached的服务信息，进程信息，内存信息
        :return: {'soft_info':soft_info,'pro_info':pro_info,'memory_info':memory_info}
        """
        try:
            memcache_info = json.loads(public.readFile(self.json_path))['memcached']
            return memcache_info
        except:
            # public.print_log(traceback.format_exc())
            return {"soft_info": "软件查询出错"}

    def __get_apache_status(self) -> Dict:
        """
        获取apache的服务信息，进程信息，内存信息
        :return:{'soft_info':soft_info,'pro_info':pro_info,'memory_info':memory_info}
        """
        try:
            httpd_info = json.loads(public.readFile(self.json_path))['httpd']
            return httpd_info
        except:
            # public.print_log(traceback.format_exc())
            return {"soft_info": "软件查询出错"}

    def __get_ftp_status(self) -> Dict:
        """
        获取ftp的连接情况，进程信息，内存信息
        :return: {'soft_info':soft_info,'pro_info':pro_info,'memory_info':memory_info}
        """
        try:
            ftp_info = json.loads(public.readFile(self.json_path))['pure-ftpd']
            return ftp_info
        except:
            return {'soft_info': '软件信息查询出错'}

    def __get_tomcat_status(self) -> Dict:
        """
        获取tomcat的信息
        :return: {'soft_info':soft_info,'pro_info':pro_info,'memory_info':memory_info}
        """
        try:
            tomcat_info = json.loads(public.readFile(self.json_path))['jsvc']
            return tomcat_info
        except:
            return {"soft_info": "软件查询出错"}

    def __get_docker_status(self) -> Dict:
        """
        获取docker的服务容器信息，docker进程信息，docker使用内存信息
        :return: {'soft_info':{'容器名:镜像名:镜像版本':{容器详细使用信息}...},'pro_info':pro_info,'memory_info':memory_info}
        """
        try:
            docker_info = json.loads(public.readFile(self.json_path))['dockerd']
            public.print_log(docker_info)
            return docker_info
        except:
            return {"soft_info": "软件查询出错"}

    def __get_sever_status_list(self) -> List:
        """
        查询服务存在列表
        :return:【服务名，。。。】
        """
        try:
            import psutil
        except:
            os.system("btpip intsall psutil")
            import psutil
        try:
            all_sever_name_list = ['nginx', 'mysqld_safe', 'redis-server', 'mongod', 'postgres', 'memcached', 'httpd',
                                   'pure-ftpd', 'jsvc', 'dockerd']
            survive_sever_list = []
            processes = psutil.process_iter()
            for proc in processes:
                if proc.name() in all_sever_name_list:
                    if proc.name() == 'jsvc':
                        if proc.exe() == "/www/server/tomcat/bin/jsvc":
                            survive_sever_list.append(proc.name())
                        continue
                    if int(proc.ppid()) == 1:
                        survive_sever_list.append(proc.name())
            return list(set(survive_sever_list))
        except:
            # public.print_log(traceback.format_exc())
            return public.returnMsg(False, "服务列表信息查询出错")

    def __get_tomcat_usr_info(self) -> Dict:
        try:
            tomcat_status = False
            if 'jsvc' in self.__get_sever_status_list(): tomcat_status = True
            user_path = '/www/server/tomcat/conf/tomcat-users.xml'
            if os.path.exists(user_path):
                conf = public.readFile(user_path)
                user_info = '<user username="admin" password="admin" roles="manager-gui"/>'
                if user_info not in conf:
                    return {'status': False, 'soft_introduction': self.soft_introduction['jsvc'],
                            'tomcat_status': tomcat_status}
            return {'status': True, 'soft_introduction': self.soft_introduction['jsvc'], 'tomcat_status': tomcat_status}
        except:
            return {'status': False, 'soft_introduction': self.soft_introduction['jsvc'],
                    'tomcat_status': tomcat_status}

    def __mongod_admin(self, option: str) -> Dict:
        try:
            statusString = self.statusOption[option]
            Command = {"start": "/etc/init.d/mongodb start",
                       "stop": "/etc/init.d/mongodb stop", }
            if option != '2':
                public.ExecShell(Command.get(statusString))
                return public.returnMsg(True, '操作成功!')
            public.ExecShell(Command.get('stop'))
            public.ExecShell(Command.get('start'))
            return public.returnMsg(True, '操作成功!')
        except:
            # public.print_log(traceback.format_exc())
            return public.returnMsg(False, '操作失败!')

    def __redis_admin(self, option: str) -> Dict:
        try:
            statusString = self.statusOption[option]
            get = public.dict_obj()
            get.name = 'redis'
            get.type = statusString

            return self.syst.ServiceAdmin(get)
        except:
            return public.returnMsg(False, '操作失败!')

    def __memcached_admin(self, option: str) -> Dict:
        try:
            statusString = self.statusOption[option]
            get = public.dict_obj()
            get.name = 'memcached'
            get.type = statusString
            return self.syst.ServiceAdmin(get)
        except:
            return public.returnMsg(False, '操作失败!')

    def __docker_admin(self, option: str) -> Dict:
        try:
            s_type = self.statusOption[option]
            exec_str = 'systemctl {} docker.socket'.format(s_type)
            public.ExecShell(exec_str)
            if s_type in ['start', 'restart']:
                try:
                    import docker
                    self.__docker = docker.from_env()
                except:
                    return public.returnMsg(True, 'Docker 链接失败。请检查Docker是否正常启动')
                for container in self.__docker.containers.list(all=True):
                    try:
                        container.start()
                    except:
                        pass
            return public.returnMsg(True, "操作成功")
        except:
            return public.returnMsg(False, '操作失败!')

    def __tomcat_admin(self, option: str) -> Dict:
        try:
            statusString = self.statusOption[option]
            get = public.dict_obj()
            get.name = 'tomcat'
            get.type = statusString
            self.syst.ServiceAdmin(get)
            return public.returnMsg(True, '操作成功!')
        except:
            return public.returnMsg(False, '操作失败!')

    def __ftp_admin(self, option: str) -> Dict:
        try:
            statusString = self.statusOption[option]
            get = public.dict_obj()
            get.name = 'pure-ftpd'
            get.type = statusString
            return self.syst.ServiceAdmin(get)
        except:
            return public.returnMsg(False, '操作失败!')

    def __apache_admin(self, option: str) -> Dict:
        try:
            statusString = self.statusOption[option]
            get = public.dict_obj()
            get.name = 'apache'
            get.type = statusString
            res = self.syst.ServiceAdmin(get)
            import time
            time.sleep(1)
            return res
        except:
            return public.returnMsg(False, '操作失败!')

    def __mysqld_admin(self, option: str) -> Dict:
        try:
            statusString = self.statusOption[option]
            get = public.dict_obj()
            get.name = 'mysqld'
            get.type = statusString
            return self.syst.ServiceAdmin(get)
        except:
            return public.returnMsg(False, '操作失败!')

    def __nginx_admin(self, option: str) -> Dict:
        try:
            statusString = self.statusOption[option]
            get = public.dict_obj()
            get.name = 'nginx'
            get.type = statusString
            return self.syst.ServiceAdmin(get)
        except:
            return public.returnMsg(False, '操作失败!')

    def __pgsql_admin(self, option: str) -> Dict:
        try:
            statusString = self.statusOption[option]
            get = public.dict_obj()
            get.name = 'pgsql'
            get.type = statusString
            return self.syst.ServiceAdmin(get)
        except:
            return public.returnMsg(False, '操作失败!')

    # 结束进程树
    def __kill_process_all(self, pid: str) -> Dict:
        import psutil
        if pid < 30: return public.returnMsg(True, '已结束此进程树!')
        try:
            if pid not in psutil.pids(): public.returnMsg(True, '已结束此进程树!')
            p = psutil.Process(pid)
            ppid = p.ppid()
            name = p.name()
            p.kill()
            public.ExecShell('pkill -9 ' + name)
            if name.find('php-') != -1:
                public.ExecShell("rm -f /tmp/php-cgi-*.sock")
            elif name.find('mysql') != -1:
                public.ExecShell("rm -f /tmp/mysql.sock")
            elif name.find('mongod') != -1:
                public.ExecShell("rm -f /tmp/mongod*.sock")
            self.__kill_process_lower(pid)
            if ppid: return self.kill_process_all(ppid)
            return public.returnMsg(True, '已结束此进程!')
        except:
            return public.returnMsg(False, '结束进程失败!')

    def __kill_process_lower(self, pid: int) -> bool:
        import psutil
        pids = psutil.pids()
        for lpid in pids:
            if lpid < 30: continue
            p = psutil.Process(lpid)
            ppid = p.ppid()
            if ppid == pid:
                p.kill()
                return self.__kill_process_lower(lpid)
        return True

    def get_page(self, data: List, get: Dict) -> Dict:
        # 包含分页类
        import page
        # 实例化分页类
        page = page.Page()
        info = {}
        info['count'] = len(data)
        info['row'] = self.ROWS
        info['p'] = 1
        if hasattr(get, 'p'):
            try:
                info['p'] = int(get['p'])
            except:
                info['p'] = 1
        info['uri'] = {}
        info['return_js'] = ''
        if hasattr(get, 'tojs'):
            info['return_js'] = get.tojs

        # 获取分页数据
        result = {}
        result['page'] = page.GetPage(info, '1,2,3,4,5,8')
        n = 0
        result['data'] = []
        for i in range(info['count']):
            if n >= page.ROW: break
            if i < page.SHIFT: continue
            n += 1
            result['data'].append(data[i])
        return result

    def set_status(self, get: Dict) -> Dict:
        try:
            if os.path.exists(self.json_path) and public.readFile(self.json_path) != '':
                data = json.loads(public.readFile(self.json_path))
            else:
                data = {"mysqld_safe": {},
                        "redis-server": {},
                        "mongod": {},
                        "postgres": {},
                        "nginx": {},
                        "memcached": {},
                        "httpd": {},
                        "pure-ftpd": {},
                        "jsvc": {},
                        "dockerd": {},
                        "status": 0}
            if not data.get('status', 0):
                data['status'] = 0
            data['status'] = get.status
            public.writeFile(self.json_path, json.dumps(data))

            if int(data['status']):
                self.set_cron()
            else:
                self.del_cron()
            return public.returnMsg(True, "设置成功")
        except:
            pass
            # public.print_log(traceback.format_exc())

    def set_cron(self) -> NoReturn:
        """
        设置常用软件监控
        :return:
        """
        try:
            import crontab
            if public.M('crontab').where('name=?', u'[勿删]常用软件资源监视进程').count():
                return
            s_body = '''btpython /www/server/panel/class/monitorModel/push_soft_status.py '''
            args = {
                "name": u'[勿删]常用软件资源监视进程',
                "type": 'minute-n',
                "where1": 5,
                "hour": '',
                "minute": '',
                "week": '',
                "sType": "toShell",
                "sName": "",
                "backupTo": "",
                "save": '',
                "sBody": s_body,
                "urladdress": "undefined"
            }
            p = crontab.crontab()
            id = p.AddCrontab(args)
            p.StartTask(id)
        except:
            pass

    def del_cron(self) -> NoReturn:
        try:
            import crontab
            p = crontab.crontab()
            crontab_data = p.GetCrontab('')
            for i in crontab_data:
                if i['name'] == u'[勿删]常用软件资源监视进程':
                    p.DelCrontab({'id': i['id']})
                    break
        except:
            # public.print_log(traceback.format_exc())
            pass

    def get_log(self, get) -> Dict or List:
        try:
            if not hasattr(get, 'name'):
                return public.returnMsg(False, "请指定软件")
            log_path_map = {
                'Nginx': self.__get_nginx_log_path,
                'Php': self.__get_php_log_path,
                'Mongodb': self.__get_mongo_log_path,
                'Memcache': self.__get_memcache_log_path,
                'Redis': self.__get_redis_log_path,
                'Apache': self.__get_apache_log_path,
                'Pgsql': self.__get_postgress_log_path,
            }
            if get.name not in log_path_map.keys():
                return public.returnMsg(False, "请指定正确软件")
            if get.name == 'Docker':
                return log_path_map[get.name](get)
            path = log_path_map[get.name]()
            if type(path) == list:
                if get.name == 'Php':
                    logs = []
                    php_path = '/www/server/php/'
                    file_list = os.listdir(php_path)
                    for i in range(len(file_list)):
                        log = self.__GetOpeLogs(path[i])
                        log['msg'] = self.__search_log(log['msg'], get)
                        log.update({'version': file_list[i]})
                        logs.append(log)
                    logs = sorted(logs, key=lambda x: x['version'], reverse=True)
                    return logs
            else:
                logs = self.__GetOpeLogs(path)
                logs['msg'] = self.__search_log(logs['msg'], get)
                return logs
        except:
            pass
            # public.print_log(traceback.format_exc())

    def __search_log(self, log, get):
        if hasattr(get, 'search'):
            if get.search != '':
                msg_l = log.split('\n')
                msg_l = [i for i in msg_l if get.search.lower() in i.lower()]
                log = '\n'.join(msg_l)
        return log

    # 取指定日志
    def __GetOpeLogs(self, path: str) -> Dict:
        try:
            if not os.path.exists(path):
                return public.returnMsg(False, 'AJAX_LOG_FILR_NOT_EXISTS')
            if public.readFile(path) == '':
                return public.returnMsg(True, '')
            return public.returnMsg(
                True, public.xsssec(public.GetNumLines(path, 1000)))
        except:
            return public.returnMsg(False, '')

    def get_docker_log(self, get) -> Dict:
        try:
            if get.name != 'Docker':
                return ''
            logs = public.M('logs').where('type=?', 'Docker module').select()
            if hasattr(get, 'search'):
                if get.search != '':
                    logs = [i for i in logs if
                            get.search in i['log'] or get.search in i['addtime'] or get.search in i['username']]
            self.ROWS = 10
            if hasattr(get, 'ROWS'):
                self.ROWS = int(get.ROWS)
            l = self.get_page(logs, get)
            return l
        except:
            pass

    def __get_nginx_log_path(self) -> str:
        try:
            path = '/www/wwwlogs/nginx_error.log'
            if os.path.exists(path):
                return path
            return ''
        except:
            return ''

    def __get_postgress_log_path(self) -> str:
        path = '/www/server/pgsql/logs/pgsql.log'
        if os.path.exists(path):
            return path
        else:
            return ''

    def __get_php_log_path(self) -> str:
        try:
            path_l = []
            path = '/www/server/php/'
            file_list = os.listdir(path)
            for i in file_list:
                path_l.append(path + i + '/var/log/php-fpm.log')
            return path_l
        except:
            return []

    def __get_memcache_log_path(self) -> str:
        try:
            txt = public.ExecShell('journalctl -u memcached.service > /www/wwwlogs/memcache.log 2>&1')[1]
            if not txt:
                return '/www/wwwlogs/memcache.log'
            else:
                return ''
        except:
            return ''

    def __get_redis_log_path(self) -> str:
        try:
            log_path = '/www/server/redis/redis.log'
            if os.path.exists(log_path):
                return log_path
            else:
                return ''
        except:
            return ''

    def __get_apache_log_path(self) -> str:
        try:
            log_path = '/www/wwwlogs/error_log'
            if os.path.exists(log_path):
                return log_path
            else:
                return ''
        except:
            return ''

    def __get_mongo_log_path(self) -> str:
        try:
            mongo_path = '/www/server/mongodb/config.conf'
            if os.path.exists(mongo_path):
                conf = public.readFile(mongo_path)
                tmp = re.findall('path' + ":\s+(.+)", conf)
                if not tmp: return ""
                return tmp[0]
            return ''
        except:
            return ''

    def soft_log_list(self, get: Dict) -> List:
        try:
            soft_list = ['nginx', 'httpd', 'mysqld_safe',  'redis-server', 'php', 'pure-ftpd',  'mongod', 'postgres', 'memcached',
                          'dockerd']
            name_map = {'pure-ftpd': 'FTP', 'mysqld_safe': 'Mysql', 'redis-server': 'Redis', 'mongod': 'Mongodb',
                        'postgres': 'Pgsql', 'memcached': 'Memcache', 'httpd': 'Apache',
                        'nginx': 'Nginx', 'php': 'Php', 'dockerd': 'Docker'}
            soft_list = [i for i in soft_list if self.__is_installation(i)]
            if 'postgres' in soft_list:
                if not self.__is_installation('postgres')['pgsql']:
                    soft_list.remove('postgres')
            soft_list = [name_map[i] for i in soft_list]
            return soft_list
        except:
            pass


if __name__ == '__main__':
    a = main()
    main.set_status(1)
