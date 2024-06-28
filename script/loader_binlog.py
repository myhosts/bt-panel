
import os,sys
panel_path = '/www/server/panel'
os.chdir(panel_path)
if not 'class/' in sys.path: sys.path.insert(0,'class/')

import PluginLoader
import public

if __name__ == '__main__':
    import argparse
    args_obj = argparse.ArgumentParser(usage="必要的参数：--db_name 数据库名称!")
    args_obj.add_argument("--db_name", help="数据库名称!")
    args_obj.add_argument("--binlog_id", help="任务id")
    args = args_obj.parse_args()
    if not args.db_name:
        args_obj.print_help()

    get = public.dict_obj()
    get.model_index = "project"
    get.db_name = args.db_name
    get.binlog_id = args.binlog_id
    PluginLoader.module_run("binlog", "execute_by_comandline", get)

