#coding: utf-8
#  + -------------------------------------------------------------------
# | 宝塔Linux面板
#  + -------------------------------------------------------------------
# | Copyright (c) 2015-2016 宝塔软件(http:#bt.cn) All rights reserved.
#  + -------------------------------------------------------------------
# | Author: hwliang <hwl@bt.cn>
#  + -------------------------------------------------------------------
import public, db, re, os, firewalls
try:
    from BTPanel import session
except:
    pass


class ftp:
    __runPath = None

    def __init__(self):
        self.__runPath = '/www/server/pure-ftpd/bin'

    def AddUser(self, get):
        """
        @name 添加FTP用户
        @param path 保存路径
        @param ftp_username FTP用户名
        @param ftp_password FTP密码
        @param ps 备注
        """
        try:
            if not os.path.exists('/www/server/pure-ftpd/sbin/pure-ftpd'):
                return public.returnMsg(False, '请先到软件商店安装Pure-FTPd服务')
            import files, time
            fileObj = files.files()

            get['ftp_username'] = get['ftp_username'].replace(' ', '')
            if re.search("\W+", get['ftp_username']):
                return {
                    'status': False,
                    'code': 501,
                    'msg': public.getMsg('FTP_USERNAME_ERR_T')
                }
            if len(get['ftp_username']) < 3:
                return {
                    'status': False,
                    'code': 501,
                    'msg': public.getMsg('FTP_USERNAME_ERR_LEN')
                }
            if not fileObj.CheckDir(get['path']):
                return {
                    'status': False,
                    'code': 501,
                    'msg': public.getMsg('FTP_USERNAME_ERR_DIR')
                }
            if public.M('ftps').where('name=?',
                                      (get.ftp_username.strip(), )).count():
                return public.returnMsg(False, 'FTP_USERNAME_ERR_EXISTS',
                                        (get.ftp_username, ))
            username = get['ftp_username'].strip()
            password = get['ftp_password'].strip()

            if len(password) < 6:
                return public.returnMsg(False, 'FTP密码长度不能少于6位!')
            get.path = get['path'].strip()
            get.path = get.path.replace("\\", "/")
            fileObj.CreateDir(get)
            public.ExecShell('chown www.www ' + get.path)
            public.ExecShell(self.__runPath + '/pure-pw useradd "' + username +
                             '" -u www -d ' + get.path + '<<EOF \n' +
                             password + '\n' + password + '\nEOF')
            self.FtpReload()
            ps = public.xssencode2(get['ps'])
            if get['ps'] == '': ps = public.getMsg('INPUT_PS')
            addtime = time.strftime('%Y-%m-%d %X', time.localtime())

            pid = 0
            if hasattr(get, 'pid'): pid = get.pid
            public.M('ftps').add(
                'pid,name,password,path,status,ps,addtime',
                (pid, username, password, get.path, 1, ps, addtime))
            public.WriteLog('TYPE_FTP', 'FTP_ADD_SUCCESS', (username, ))
            return public.returnMsg(True, 'ADD_SUCCESS')
        except Exception as ex:
            public.WriteLog('TYPE_FTP', 'FTP_ADD_ERR', (username, str(ex)))
            return public.returnMsg(False, 'ADD_ERROR')

    #删除用户
    def DeleteUser(self, get):
        try:
            username = get['username']
            id = get['id']
            if public.M('ftps').where("id=? and name=?", (id,username, )).count()==0:
                return public.returnMsg(False, 'DEL_ERROR')

            public.ExecShell(self.__runPath + '/pure-pw userdel "' + username +
                             '"')
            self.FtpReload()
            public.M('ftps').where("id=?", (id, )).delete()
            public.WriteLog('TYPE_FTP', 'FTP_DEL_SUCCESS', (username, ))
            return public.returnMsg(True, "DEL_SUCCESS")
        except Exception as ex:
            public.WriteLog('TYPE_FTP', 'FTP_DEL_ERR', (username, str(ex)))
            return public.returnMsg(False, 'DEL_ERROR')

    #修改用户密码
    def SetUserPassword(self, get):
        try:
            id = get['id']
            username = get['ftp_username'].strip()
            password = get['new_password'].strip()
            if len(password) < 6:
                return public.returnMsg(False, 'FTP密码长度不能少于6位!')
            if public.M('ftps').where("id=? and name=?", (id,username, )).count()==0:
                return public.returnMsg(False, 'EDIT_ERROR')
            public.ExecShell(self.__runPath + '/pure-pw passwd "' + username +
                             '"<<EOF \n' + password + '\n' + password +
                             '\nEOF')
            self.FtpReload()
            public.M('ftps').where("id=?",
                                   (id, )).setField('password', password)
            public.WriteLog('TYPE_FTP', 'FTP_PASS_SUCCESS', (username, ))
            return public.returnMsg(True, 'EDIT_SUCCESS')
        except Exception as ex:
            public.WriteLog('TYPE_FTP', 'FTP_PASS_ERR', (username, str(ex)))
            return public.returnMsg(False, 'EDIT_ERROR')

    #设置用户状态
    def SetStatus(self, get):
        msg = public.getMsg('OFF')
        if get.status != '0': msg = public.getMsg('ON')
        try:
            id = get['id']
            username = get['username']
            status = get['status']
            if public.M('ftps').where("id=? and name=?", (id,username, )).count()==0:
                return public.returnMsg(False, 'EDIT_ERROR')
            if int(status) == 0:
                public.ExecShell(self.__runPath + '/pure-pw usermod "' +
                                 username + '" -r 1')
            else:
                public.ExecShell(self.__runPath + '/pure-pw usermod "' +
                                 username + "\" -r ''")
            self.FtpReload()
            public.M('ftps').where("id=?", (id, )).setField('status', status)
            public.WriteLog('TYPE_FTP', 'FTP_STATUS', (msg, username))
            return public.returnMsg(True, 'SUCCESS')
        except Exception as ex:
            public.WriteLog('TYPE_FTP', 'FTP_STATUS_ERR',
                            (msg, username, str(ex)))
            return public.returnMsg(False, 'FTP_STATUS_ERR', (msg, ))

    '''
     * 设置FTP端口
     * @param Int _GET['port'] 端口号
     * @return bool
     '''

    def setPort(self, get):
        try:
            port = get['port'].strip()
            if not port: return public.returnMsg(False, 'FTP端口不能为空')
            if int(port) < 1 or int(port) > 65535:
                return public.returnMsg(False, 'PORT_CHECK_RANGE')
            data = public.ExecShell("ss -nultp|grep -w '%s '" % port)[0]
            if data: return public.returnMsg(False, "PORT_CHECK_EXISTS", [port])
            file = '/www/server/pure-ftpd/etc/pure-ftpd.conf'
            conf = public.readFile(file)
            rep = u"\n#?\s*Bind\s+[0-9]+\.[0-9]+\.[0-9]+\.+[0-9]+,([0-9]+)"
            #preg_match(rep,conf,tmp)
            conf = re.sub(rep, "\nBind        0.0.0.0," + port, conf)
            public.writeFile(file, conf)
            public.ExecShell('/etc/init.d/pure-ftpd restart')
            public.WriteLog('TYPE_FTP', "FTP_PORT", (port, ))
            #添加防火墙
            #data = ftpinfo(port=port,ps = 'FTP端口')
            get.port = port
            get.ps = public.getMsg('FTP_PORT_PS')
            firewalls.firewalls().AddAcceptPort(get)
            session['port'] = port
            return public.returnMsg(True, 'EDIT_SUCCESS')
        except Exception as ex:
            public.WriteLog('TYPE_FTP', 'FTP_PORT_ERR', (str(ex), ))
            return public.returnMsg(False, 'EDIT_ERROR')

    #重载配置
    def FtpReload(self):
        public.ExecShell(
            self.__runPath +
            '/pure-pw mkdb /www/server/pure-ftpd/etc/pureftpd.pdb')

    def get_login_logs(self, get):
        import ftplog
        ftpobj = ftplog.ftplog()
        return ftpobj.get_login_log(get)

    def get_action_logs(self, get):
        import ftplog
        ftpobj = ftplog.ftplog()
        return ftpobj.get_action_log(get)

    def set_ftp_logs(self, get):
        import ftplog
        ftpobj = ftplog.ftplog()
        result = ftpobj.set_ftp_log(get)
        return result