# coding: utf-8
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: cjxin <cjxin@bt.cn>
# -------------------------------------------------------------------

# 备份
# ------------------------------
import os, json, psutil, time, datetime
import public
import db


class main(object):
    __plugin_path = '/www/server/total'
    data_dir = None
    history_data_dir = None
    __frontend_path = '/www/server/panel/plugin/total'

    def __init__(self):
        pass

    def get_time_interval(self, local_time):
        time_key_format = "%Y%m%d00"
        start = int(time.strftime(time_key_format, local_time))
        time_key_format = "%Y%m%d23"
        end = int(time.strftime(time_key_format, local_time))
        return start, end

    def get_time_interval_hour(self, local_time,second):
        start = int(time.mktime(local_time) - second)
        start_str = time.strftime("%Y%m%d%H", time.localtime(start))
        end_str = time.strftime("%Y%m%d%H", local_time)
        return start_str, end_str

    def get_last_days(self, day):
        now = time.localtime()
        if day == 30:
            last_month = now.tm_mon - 1
            if last_month <= 0:
                last_month = 12
            import calendar
            _, last_month_days = calendar.monthrange(now.tm_year, last_month)
            day = last_month_days
        else:
            day += 1

        t1 = time.mktime(
            (now.tm_year, now.tm_mon, now.tm_mday - day, 0, 0, 0, 0, 0, 0))
        t2 = time.localtime(t1)
        start, _ = self.get_time_interval(t2)
        _, end = self.get_time_interval(now)
        start_7_day_hour, end_7_day_hour = self.get_time_interval_hour(now,604800)
        start_one_day_hour, end_one_day_hour = self.get_time_interval_hour(now,86400)
        start_hour, end_hour = self.get_time_interval_hour(now,3600)
        return [start, end,
                start_one_day_hour, end_one_day_hour,
                start_hour, end_hour,
                start_7_day_hour, end_7_day_hour]

    def __read_frontend_config(self):
        config_json = self.__frontend_path + "/config.json"
        data = {}
        if os.path.exists(config_json):
            data = json.loads(public.readFile(config_json))
        return data

    def get_default_site(self):
        config = self.__read_frontend_config()
        default = None
        if "default_site" in config:
            default = config["default_site"]
        if not default:
            site = public.M('sites').field('name').order("addtime").find()
            default = site["name"]
        return default

    def __get_file_json(self, filename, defaultv={}):
        try:
            if not os.path.exists(filename): return defaultv
            return json.loads(public.readFile(filename))
        except:
            os.remove(filename)
            return defaultv

    def get_site_settings(self, site):
        """获取站点配置"""

        config_path = "/www/server/total/config.json"
        config = self.__get_file_json(config_path)
        if not config:
            return {}

        if site not in config.keys():
            res_config = config["global"]
            res_config["push_report"] = False
        else:
            res_config = config[site]

        for k, v in config["global"].items():
            if k not in res_config.keys():
                if k == "push_report":
                    res_config[k] = False
                else:
                    res_config[k] = v
        res_config["default_site"] = self.get_default_site()
        return res_config

    def get_data_dir(self):
        if self.data_dir is None:
            default_data_dir = os.path.join(self.__plugin_path, "logs")
            settings = self.get_site_settings("global")
            if "data_dir" in settings.keys():
                config_data_dir = settings["data_dir"]
            else:
                config_data_dir = default_data_dir
            self.data_dir = default_data_dir if not config_data_dir else config_data_dir
        return self.data_dir

    def get_log_db_path(self, site, db_name="logs.db", history=False):
        site = site.replace('_', '.')
        if not history:
            data_dir = self.get_data_dir()
            db_path = os.path.join(data_dir, site, db_name)
        else:
            data_dir = self.get_history_data_dir()
            db_name = "history_logs.db"
            db_path = os.path.join(data_dir, site, db_name)
        return db_path

    def get_history_data_dir(self):
        if self.history_data_dir is None:
            default_history_data_dir = os.path.join(self.__plugin_path, "logs")
            settings = self.get_site_settings("global")
            if "history_data_dir" in settings.keys():
                config_data_dir = settings["history_data_dir"]
            else:
                config_data_dir = default_history_data_dir
            self.history_data_dir = default_history_data_dir if not config_data_dir else config_data_dir
        return self.history_data_dir

    def get_site_flow(self, site, start_date, end_date):
        """获取站点总流量"""
        db_path = self.get_log_db_path(site, db_name='total.db')
        ts = db.Sql()
        ts.dbfile(db_path)
        total_flow = 0
        if not ts:
            return total_flow
        # 统计数据
        ts.table("request_stat").field('sum(length) as length')
        ts.where("time between ? and ?", (start_date, end_date))
        sum_data = ts.find()

        if type(sum_data) != dict:
            sum_data['length'] = 0
            return sum_data

        total_flow = sum_data['length'] if sum_data['length'] else 0

        return total_flow

    def get_realtime_traffic(self, site=None):
        """获取实时流量"""
        res_data = []
        if site is not None:
            flow_file = self.__plugin_path + "/logs/{}/flow_sec.json".format(
                site)
            if not os.path.isfile(flow_file):
                return res_data
            flow_data = public.readFile(flow_file)
            datetime_now = datetime.datetime.now()
            lines = flow_data.split("\n")
            for line in lines:
                if not line: continue
                try:
                    _flow, _write_time = line.split(",")
                    datetime_log = datetime.datetime.fromtimestamp(
                        float(_write_time))
                    datetime_interval = datetime_now - datetime_log
                    if datetime_interval.seconds < 3:
                        data = {"timestamp": _write_time, "flow": int(_flow)}
                        res_data.append(data)

                except Exception as e:
                    print("Real-time traffic error:", str(e))
            if len(res_data) > 1:
                res_data.sort(key=lambda o: o["timestamp"], reverse=True)
        return res_data

    def get_site_overview_sum_data(self, site, start_date, end_date):
        """获取站点流量数据"""
        sum_data = {}
        db_path = self.get_log_db_path(site, db_name='total.db')
        ts = db.Sql()
        ts.dbfile(db_path)
        if not ts:
            return sum_data
        # 统计数据
        ts.table("request_stat").field('time,length')
        ts.where("time between ? and ?", (start_date, end_date))
        sum_data = ts.select()
        return sum_data

    def get_site_traffic(self, get):
        """
       @获取网站总流量和实时流量
       @return
           data : 网站总流量和实时流量
           data:{
                'site':{
                'total_flow': 网站总流量
                'realtime_traffic': 实时流量
                }
           }
       """
        if not os.path.exists(self.__frontend_path):
            return {'data': {}, 'msg': '请先安装网站监控报表！', 'status': False}

        try:
            date = self.get_last_days(30)
            sites = public.M('sites').field('name').order("addtime").select()
            data = {}
            msg = True
            for site_info in sites:
                try:
                    site = site_info["name"]
                    data[site] = {
                        'total_flow': 0,
                        '7_day_total_flow': 0,
                        'one_day_total_flow': 0,
                        'one_hour_total_flow': 0
                        # 'realtime_traffic': realtime_traffic
                    }
                    for key in data[site].keys():
                        if key == "total_flow":
                            start_date = date[0]
                            end_date = date[1]
                        elif key == "one_day_total_flow":
                            start_date = date[2]
                            end_date = date[3]
                        elif key == "one_hour_total_flow":
                            start_date = date[4]
                            end_date = date[5]
                        elif key == "l7_day_total_flow":
                            start_date = date[6]
                            end_date = date[7]
                        data[site][key] = self.get_site_flow(
                            site,
                            start_date,
                            end_date
                        )
                    # realtime_traffic_list = self.get_realtime_traffic(site)
                    # if len(realtime_traffic_list) > 0:
                    #     realtime_traffic = realtime_traffic_list[0]["flow"]
                    # else:
                    #     realtime_traffic = 0
                except Exception as e:
                    msg = str(e)
                    if msg.find("object does not support item assignment") != -1:
                        msg = "数据文件/www/server/total/logs/{}/logs.db已损坏。".format(site)

            return {'data': data, 'msg': msg, 'status': True}

        except Exception as e:
            return {'data': {}, 'msg': e, 'status': False}

    def get_all_site_flow(self, get):
        """
        @获取网站流量数据
        @param get['start'] 开始时间
        @param get['end'] 结束时间
        @return
            data' : 网站流量数据
            data:{
                [
                {'time': 时间戳, 'length': 网站总流量}
                ]
            }
        """
        if not os.path.exists(self.__frontend_path):
            return {'data': {}, 'msg': '请先安装网站监控报表！', 'status': False}

        try:
            msg = True
            time_key_format = "%Y%m%d%H"
            start_date = int(get.start)
            end_date = int(get.end)
            start_date = int(time.strftime(time_key_format, time.localtime(start_date)))
            end_date = int(time.strftime(time_key_format, time.localtime(end_date)))

            list_data = []
            sites = public.M('sites').field('name').order("addtime").select()
            for site_info in sites:
                try:
                    site = site_info["name"]
                    site_overview_info = self.get_site_overview_sum_data(site, start_date, end_date)
                    if site_overview_info:
                        list_data.append(site_overview_info)

                except Exception as e:
                    msg = str(e)
                    if msg.find("object does not support item assignment") != -1:
                        msg = "数据文件/www/server/total/logs/{}/logs.db已损坏。".format(site)

            data = dict()
            for site_info in list_data:
                for i in site_info:
                    if data.get(i['time']):
                        data[i['time']] += i['length']
                    else:
                        data[i['time']] = i['length']

            result = [{'time': k, 'length': v} for k, v in data.items()]

            def sort_key(d):
                return d['time']

            result.sort(key=sort_key, reverse=False)

            return {'data': result, 'msg': msg, 'status': True}
        except Exception as e:
            return {'data': [], 'msg': e, 'status': False}
