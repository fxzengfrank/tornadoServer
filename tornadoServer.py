#!/usr/bin/env python
# _*_ coding: utf-8 _*_

import os
import time
import json
import logging
import traceback

import urlparse

from threading import Thread

from tornado import web, websocket, ioloop
from tornado.httpserver import HTTPServer
from tornado.log import enable_pretty_logging

enable_pretty_logging()

session_dict = dict()

class WebServer():
    def __init__(self, main, opts):
        self.main = main
        self.opts = opts
        self.main_dir = main.main_dir
        self.web_dir = os.path.join(self.main_dir, 'web')
        self.ssl_dir = os.path.join(self.web_dir, 'ssl')
        self.static_dir = os.path.join(self.web_dir, 'static')
        self.template_dir = os.path.join(self.web_dir, 'template')
        self.component_dir = os.path.join(self.template_dir, 'component')
        enable_pretty_logging()
        self.application = web.Application([
            (r'/', IndexHandler, dict(main=self.main)),
            (r'/login/?', LoginHandler, dict(main=self.main)),
            (r'/logout/?', LogoutHandler, dict(main=self.main)),
            (r"/confirm/?", ConfirmHandler, dict(main=self.main)),
            (r'/authorize/?', AuthorizeHandler, dict(main=self.main)),
            (r'/check_session/?', SessionHandler, dict(main=self.main)),
            (r'/static/(.*)', web.StaticFileHandler, dict(path=self.static_dir)),
            (r'/(favicon.ico)', web.StaticFileHandler, dict(path=self.static_dir)),
            (r'/api/db((/(.*))?)', apiDBHandler, dict(main=self.main)),
            (r'/api/role((/(.*))?)', apiRoleHandler, dict(main=self.main)),
            (r'/api/group((/(.*))?)', apiGroupHandler, dict(main=self.main)),
            (r'/api/user/aam((/(.*))?)', apiAAMUserHandler, dict(main=self.main)),
            (r'/api/user/local((/(.*))?)', apiLocalUserHandler, dict(main=self.main)),
            (r'/api/session((/(.*))?)', apiSessionHandler, dict(main=self.main)),
            (r'/admin', AdminHandler, dict(main=self.main)),
            (r'/agent', AgentHandler, dict(main=self.main)),    #   Not finished yet
            (r'/session_info', SessionInfoHandler, dict(main=self.main)),
        ],
            static_path = self.static_dir,
            template_path = self.template_dir,
            cookie_secret = "61oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
            login_url = "/login",
            autoreload = self.opts['autoreload'],
            debug = True,
            xsrf_cookies = False,
        )
        if opts['ssl']:
            ssl_options = {
                'certfile': os.path.join(self.ssl_dir, opts['certfile']),
                'keyfile': os.path.join(self.ssl_dir, opts['keyfile']),
            }
            self.http_server = HTTPServer(self.application, ssl_options=ssl_options)
        else:
            self.http_server = HTTPServer(self.application)
    def run(self):
        try:
            self.http_server.bind(self.opts['port'])
            # self.http_server.start(num_processes=1)
            self.http_server.start()
            # self.http_server.listen(self.opts['port'])
            logging.info('SSO web server started on port %d' % self.opts['port'])
            logging.info('Press "Ctrl+C" to exit.\n')
            ioloop.IOLoop.instance().current().start()
        except KeyboardInterrupt:
            print('"Ctrl+C" received, exited.\n')
        except:
            print traceback.format_exc()
        finally:
            del self.main.db
#
class BaseHandler(web.RequestHandler):
    #
    def initialize(self, main):
        self.main = main
    #
    def get_current_session(self):
        try:
            session_id = self.get_secure_cookie("sso_session_id")
            assert session_id != None
            remote_ip = self.request.remote_ip
            session = self.main.aaa.get_session(session_id, remote_ip)
            assert session != None
            return session
        except:
            return None
    #
    def get_current_user(self):
        try:
            session = self.get_current_session()
            assert session != None
            name = session['name']
            return name
        except:
            return None
    #
#
class IndexHandler(BaseHandler):
    #
    @web.authenticated
    def get(self, *args):
        self.render('index.html', user=self.get_current_user())
#
class LoginHandler(BaseHandler):
    #
    def get(self):
        next_url = self.get_argument('next', '/')
        pre_url = self.get_argument('pre', '/')
        poweredBy = self.get_argument('poweredBy', '')
        session_id = self.get_secure_cookie('sso_session_id')
        remote_ip = self.request.remote_ip
        print 'poweredBy: %s'%(poweredBy)
        print 'next: %s'%(next_url)
        try:
            session = self.main.aaa.get_session(session_id, remote_ip)
            assert session != None
            self.redirect(self._redirct_url(session_id, next_url, poweredBy))
        except:
            self.render('login.html', next_url=next_url, pre_url=pre_url, retry=False)
    #
    def post(self):
        userid = self.get_argument("userid")
        passwd = self.get_argument("password")
        pre_url = self.get_argument('pre', '/')
        next_url = self.get_argument('next', '/')
        poweredBy = self.get_argument('poweredBy', '')
        remote_ip = self.request.remote_ip
        #
        try:
            # x_real_ip = self.request.headers.get("X-Real-IP")
            # remote_ip = x_real_ip or self.request.remote_ip
            session_id = self.main.aaa.Authenticate(userid, passwd, remote_ip)
            assert session_id != None
            self.set_secure_cookie('sso_session_id', session_id, expires_days=1)
            # logging.info('%s login from %s sucessfully, session_id: %s', userid, remote_ip, session_id)
            self.redirect(self._redirct_url(session_id, next_url, poweredBy))
        except:
            logging.warning(traceback.format_exc())
            self.render('login.html', next_url=next_url, pre_url=pre_url, retry=True)
    #
    def _redirct_url(self, session_id, next_url, poweredBy):
        this_url = self.request.full_url()
        this_url_split = urlparse.urlsplit(this_url)
        next_url_split = urlparse.urlsplit(next_url)
        if next_url_split.scheme and (this_url_split.netloc != next_url_split.netloc):
            next_verify_url = next_url_split.scheme + '://' + next_url_split.netloc
            next_verify_url = urlparse.urljoin(next_verify_url, 'verify_session')
            next_url = '%s?session_id=%s&next=%s' % (next_verify_url, session_id, next_url)
            print 'next_url: %s'%(next_url)
        return next_url
#
class ConfirmHandler(BaseHandler):
    #
    def get(self):
        pre_url = self.get_argument('pre', '/')
        next_url = self.get_argument('next', '/')
        self.render(
            'confirm.html',
            pre=pre_url,
            next='logout?next=%s&pre=%s' % (next_url, pre_url)
        )
#
class LogoutHandler(BaseHandler):
    #
    # @web.authenticated
    def get(self):
        pre_url = self.get_argument('pre', '/')
        next_url = self.get_argument('next', '/')
        session_id = self.get_secure_cookie('sso_session_id')
        session_id = session_id or self.get_argument('session_id', None)
        x_real_ip = self.request.headers.get("X-Real-IP")
        remote_ip = x_real_ip or self.request.remote_ip
        if self.main.aaa.clear_session(session_id, remote_ip):
            self.clear_all_cookies()
        self.redirect('/login?pre=%s&next=%s' % (pre_url, next_url))
#
class AuthorizeHandler(BaseHandler):
    #
    def get(self, *args):
        try:
            sessionid = self.get_argument("session_id")
            role = self.get_argument("role")
            access = self.get_argument("access")
            session = self.main.db.select_dict('session', sessionid)
            assert session != None
            x_real_ip = self.request.headers.get("X-Real-IP")
            print 'x_real_ip = %s' % x_real_ip
            remote_ip = x_real_ip or self.request.remote_ip
            assert session['remote_ip'] == remote_ip
            session['timeout'] = 1800
            self.main.db.update_dict('session', sessionid, session)
            rolelist = session['role_list']
            if role in rolelist:
                #audit(remote_ip, userid, role, access)
                who = who = '%s [%s]' % (session['name'],session['userid'])
                where = remote_ip
                dowhat = 'require %s' % role
                #accounting(who, where, dowhat, succ=True)
                self.write(dict(status='permit'))
            else:
                who = who = '%s [%s]' % (session['name'],session['userid'])
                where = remote_ip
                dowhat = 'require %s' % role
                #accounting(who, where, dowhat, succ=False)
                self.write(dict(status='deny'))
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400)
#
class SessionHandler(BaseHandler):
    #
    def get(self, *args, **kwargs):
        try:
            sessionid = self.get_argument("session_id", None)
            print sessionid
            assert sessionid != None
            session = self.main.db.select_dict('session', sessionid)
            assert session != None
            x_real_ip = self.request.headers.get("X-Real-IP")
            print x_real_ip
            remote_ip = x_real_ip or self.request.remote_ip
            assert session['remote_ip'] == remote_ip
            session['timeout'] = 1800
            self.main.db.update_dict('session', sessionid, session) 
            username = session['name']
            self.write(dict(username=username, status='valid'))
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400)
#
class apiDBHandler(BaseHandler):
    #
    def get(self, *args):
        try:
            cmd = args[2]
            assert cmd in ['reload', 'flush']
            if cmd == 'reload':
                db_old = self.main.db
                self.main.load_db()
                del db_old
            elif cmd == 'flush':
                self.main.db.flush_dict('all')
            self.write('True')
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400)
#
class apiRoleHandler(BaseHandler):
    #
    @web.authenticated
    def get(self, *args):
        try:
            roleid = args[2]
            if roleid == None:
                result = self.main.db.dump_dict('role')
            else:
                result = self.main.db.select_dict('role', roleid)
            self.write(json.dumps(result))
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400)
    #
    @web.authenticated
    def post(self, *args):
        try:
            data = json.loads(self.request.body)
            assert data != None
            succ, msg = self.main.aaa.add_role(roleid=data['roleid'], name=data['name'], desc=data['desc'])
            self.write(json.dumps({'result': succ, 'message' :msg}))
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400, u'添加失败')
    #
    @web.authenticated
    def put(self, *args):
        try:
            data = json.loads(self.request.body)
            assert data != None
            succ, msg = self.main.aaa.modify_role(roleid=data['roleid'], name=data['name'], desc=data['desc'])
            self.write(json.dumps({'result': succ, 'message' :msg}))
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400)
    #
    @web.authenticated
    def delete(self, *args):
        try:
            data = json.loads(self.request.body)
            assert data != None
            succ, msg = self.main.aaa.remove_role(roleid=data['roleid'])
            self.write(json.dumps({'result': succ, 'message' :msg}))
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400)
    #
#
class apiGroupHandler(BaseHandler):
    #
    # @web.authenticated
    def get(self, *args):
        try:
            groupid = args[2]
            result_data = dict()
            if groupid == None:
                result_data['group_dict'] = self.main.db.dump_dict('group')
                # result = self.main.db.dump_dict('group')
                user_dict = dict()
                aam_user = self.main.db.dump_dict('aam_user')
                for id in aam_user:
                    name = aam_user[id]['name']
                    branchname = aam_user[id]['branchname']
                    user_dict[id] = '%s [%s - %s]' % (id, name, branchname)
                local_user = self.main.db.dump_dict('local_user')
                for id in local_user:
                    name = local_user[id]['name']
                    company = local_user[id]['company']
                    user_dict[id] = '%s [%s - %s]' % (id, name, company)
                result_data['user_dict'] = user_dict
                role_dict = dict()
                role = self.main.db.dump_dict('role')
                for id in role:
                    name = role[id]['name']
                    role_dict[id] = '%s [%s]' % (id, name)
                result_data['role_dict'] = role_dict
            else:
                result_data['group_dict'] = self.main.db.select_dict('group', groupid)
                # result = self.main.db.select_dict('group', groupid)
            self.write(json.dumps(result_data))
            # self.write(json.dumps(result))
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400)
    #
    @web.authenticated
    def post(self, *args):
        try:
            data = json.loads(self.request.body)
            assert data != None
            succ, msg = self.main.aaa.add_group(groupid=data['groupid'], name=data['name'], desc=data['desc'])
            self.write(json.dumps({'result': succ, 'message' :msg}))
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400)
    #
    @web.authenticated
    def put(self, *args):
        try:
            data = json.loads(self.request.body)
            action = data['action']
            succ, msg = False, u'未定义错误'
            if action == 'update_group':
                form_data = data['form_data']
                succ, msg = self.main.aaa.modify_group(groupid=form_data['groupid'], name=form_data['name'], desc=form_data['desc'])
            elif action == 'update_role':
                succ, msg = self.main.aaa.modify_group(groupid=data['groupid'], rolelist=data['role_list'])
            elif action == 'update_user':
                succ, msg = self.main.aaa.modify_group(groupid=data['groupid'], userlist=data['user_list'])
            self.write(json.dumps({'result': succ, 'message' :msg}))
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400)
    #
    @web.authenticated
    def delete(self, *args):
        try:
            data = json.loads(self.request.body)
            assert data != None
            succ, msg = self.main.aaa.remove_group(groupid=data['groupid'])
            self.write(json.dumps({'result': succ, 'message' :msg}))
        except:
            logging.warning(traceback.format_exc())
            raise HTTPError(400)
#
class apiAAMUserHandler(BaseHandler):
    #
    def get(self, *args):
        try:
            userid = args[2]
            if userid == None:
                result = self.main.db.dump_dict('aam_user')
            else:
                result = self.main.db.select_dict('aam_user', userid)
            self.write(json.dumps(result))
        except:
            self.write_error(400)
    #
    @web.authenticated
    def put(self, *args):
        try:
            data = json.loads(self.request.body)
            assert data != None
            succ, msg = self.main.aaa.modify_aam_user(userid=data['userid'], disabled=data['disabled'])
            self.write(json.dumps({'result': succ, 'message' :msg}))
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400)
    #
    @web.authenticated
    def delete(self, *args):
        try:
            data = json.loads(self.request.body)
            assert data != None
            succ, msg = self.main.aaa.remove_aam_user(userid=data['userid'])
            self.write(json.dumps({'result': succ, 'message' :msg}))
        except:
            logging.warning(traceback.format_exc())
            raise HTTPError(400)
    #
#
class apiLocalUserHandler(BaseHandler):
    #
    @web.authenticated
    def get(self, *args):
        try:
            userid = args[2]
            if userid == None:
                result = self.main.db.dump_dict('local_user')
            else:
                result = self.main.db.select_dict('local_user', userid)
            self.write(json.dumps(result))
        except:
            self.write_error(400)
    #
    @web.authenticated
    def post(self, *args):
        try:
            data = json.loads(self.request.body)
            assert data != None
            succ, msg = self.main.aaa.add_local_user(userid=data['userid'], name=data['name'], company=data['company'], mail=data['mail'], disabled=data['disabled'], expiredate=data['expiredate'])
            self.write(json.dumps({'result': succ, 'message' :msg}))
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400)
    #
    @web.authenticated
    def put(self, *args):
        try:
            data = json.loads(self.request.body)
            assert data != None
            if 'passwd' in data:
                succ, msg = self.main.aaa.modify_local_user_passwd(userid=data['userid'], passwd=data['passwd'])
            else:
                succ, msg = self.main.aaa.modify_local_user(userid=data['userid'], name=data['name'], company=data['company'], mail=data['mail'], disabled=data['disabled'], expiredate=data['expiredate'])
            self.write(json.dumps({'result': succ, 'message' :msg}))
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400)
    #
    @web.authenticated
    def delete(self, *args):
        try:
            data = json.loads(self.request.body)
            assert data != None
            succ, msg = self.main.aaa.remove_local_user(userid=data['userid'])
            self.write(json.dumps({'result': succ, 'message' :msg}))
        except:
            logging.warning(traceback.format_exc())
            raise HTTPError(400)
#
class apiSessionHandler(BaseHandler):
    #
    @web.authenticated
    def get(self, *args):
        try:
            sessionid = args[2]
            if sessionid == None:
                result = self.main.db.dump_dict('session')
            else:
                result = self.main.db.select_dict('session', sessionid)
            self.write(json.dumps(result))
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400)
    #
    @web.authenticated
    def delete(self, *args):
        try:
            request_data = json.loads(self.request.body)
            assert request_data != None
            for sessionid in request_data:
                self.main.db.delete_dict('session', sessionid)
            self.write(json.dumps(True))
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400)
#
class AdminHandler(BaseHandler):
    #
    # @web.authenticated
    # @authorized('sso_admin')
    def get(self):
        self.render('admin.html', tab_select=False)
#
class AgentHandler(websocket.WebSocketHandler):
    #
    def initialize(self, main):
        self.main = main
    #
    def open(self):
        pass
    #
    def on_close(self):
        pass
    #
    def on_message(self, message):
        try:
            data = json.loads(message)
        except:
            ret_data = dict(
                status='Unknown COMMAND'
            )
            self.write_message(json.dumps(ret_data))
    #
#
#   2017-11-1 by zfx
class SessionInfoHandler(BaseHandler):
    #
    def get(self, *args, **kwargs):
        try:
            sessionid = self.get_argument("session_id", None)
            assert sessionid != None
            x_real_ip = self.request.headers.get("X-Real-IP")
            remote_ip = x_real_ip or self.request.remote_ip
            session = self.main.aaa.get_session(sessionid, remote_ip)
            assert session != None
            username = session['name']
            usertype = session['usertype']
            department = session['department']
            result = dict(
                username=username,
                usertype=usertype,
                department=department,
                status='valid'
            )
            self.write(result)
        except:
            logging.warning(traceback.format_exc())
            raise web.HTTPError(400)
#
#
