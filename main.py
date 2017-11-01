#!/usr/bin/env python
# _*_ coding: utf-8 _*_

"""
If you want to use HTTPS, follow these steps:

1. Start by generating your certificate files, if you don't have them already:
# cd /root
# openssl genrsa -out server.key 2048
# openssl req -new -key server.key -out server.csr
# openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

2. Run this python script:
# python main.py --port=443 --ssl=1 --cert=server.crt --key=server.key

3. Use web browser test.
Good luck.
"""
import os
import time
import logging
import traceback
from threading import Thread
from tornado import options
from tornadoServer import WebServer

class SSO():
    aaa = None
    db = None
    server = None
    #
    def __init__(self, opts):
        self.base_filename = os.path.basename(os.path.abspath(__file__))
        self.main_dir = os.path.dirname(os.path.abspath(__file__))
        self.module_dir = os.path.join(self.main_dir, 'module')
        self.log_dir = os.path.join(self.main_dir, 'log')

        logger = logging.getLogger()
        logfile_pathname = os.path.join(self.log_dir, 'sso.run.log')
        logfile_handler = logging.FileHandler(logfile_pathname)
        logfile_fmt = '%(asctime)s %(levelname)s %(module)s.%(funcName)s.%(lineno)d %(message)s'
        logfile_formatter = logging.Formatter(fmt=logfile_fmt)
        logfile_handler.setFormatter(logfile_formatter)
        logfile_loglevel = logging.DEBUG
        logfile_handler.setLevel(logfile_loglevel)
        logger.addHandler(logfile_handler)
        logger.setLevel(logging.DEBUG)
        logging.debug('Starting %s' % self.base_filename)

        # self.aaa = AAA(self)
        # self.load_db()
        self.server = WebServer(self, opts)

        self.threadList = dict()
        self.threadList['timeout'] = Thread(target=self.clean_session)
        self.threadList['timeout'].daemon = True

        self.threadList['flushdb'] = Thread(target=self.flush_db)
        self.threadList['flushdb'].daemon = True
    #
    def run(self):
        self.threadList['timeout'].start()
        self.threadList['flushdb'].start()
        self.server.run()
    #
    def load_db(self):
        db_list = ['local_user', 'aam_user', 'group', 'role', 'session']
        # self.db = DB(self, db_list)
    #
    def flush_db(self):
        while True:
            try:
                time.sleep(180)
                if self.db.flush_dict('all'):
                    logging.info('db flush success')
                else:
                    logging.error('db flush failure')
            except:
                logging.warning(traceback.format_exc())
    #
    def clean_session(self):
        while True:
            try:
                time.sleep(10)
                session_list = self.db.list_dict('session')
                for session_id in session_list:
                    session = self.db.select_dict('session', session_id)
                    timeout = session['timeout'] - 10
                    if timeout <= 0:
                        self.db.delete_dict('session', session_id)
                        logging.info('Session %s timeout' % session_id)
                    else:
                        session['timeout'] = timeout
                        self.db.update_dict('session', session_id, session)
            except:
                logging.warning(traceback.format_exc())
    #
#
if __name__ == '__main__':
    options.define("port", default=9999, help="web server port", type=int)
    options.define("ssl", default=False, help="enable SSL", type=bool)
    options.define("cert", default='sso.crt', help="certificate file", type=str)
    options.define("key", default='sso.key', help="key file", type=str)
    options.define("auto", default=True, help="autoreload tornado", type=bool)
    options.parse_command_line()
    opts = {
        'port': options.options.port,
        'ssl': options.options.ssl,
        'certfile': options.options.cert,
        'keyfile': options.options.key,
        'autoreload': options.options.auto,
    }
    app = SSO(opts)
    app.run()
    