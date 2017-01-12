#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import time
import string
import random
import hashlib
import sqlite3
from config import DOMAIN, ADMIN_DOMAIN, DOMAIN_COUNT, DATABASE
from flask import Flask, g, request, jsonify, render_template, abort, send_from_directory

app = Flask(__name__)

# 连接SQLite3


def connect_db():
    return sqlite3.connect(DATABASE)


@app.before_request
def before_request():
    g.db = connect_db()


@app.after_request
def after_request(response):
    request_host = request.host
    # 检查是否子域名
    if request_host != ADMIN_DOMAIN and request_host.endswith('.' + DOMAIN):
        if request_host.count('.') >= DOMAIN_COUNT:
            domain = '.'.join(request_host.split('.')[-(DOMAIN_COUNT+2):])
            query = 'SELECT * FROM user where domain = ?'
            result = query_db(query, args=(domain.replace('.' + DOMAIN, ''), ))
            if not len(result):
                message = 'invalid domain'
                return jsonify(message=message)
            save()
            return jsonify(host=request.host)
    elif request_host != ADMIN_DOMAIN:
        message = 'bad domain'
        return jsonify(message=message)

    return response

@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()


# 辅助查询 字段
def query_db(query, args=(), one=False):
    cur = g.db.execute(query, args)
    rv = [dict((cur.description[idx][0], value)
               for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv


# 判断 token 是否正确
# 通过token获取所属子域名
def get_domain(token):
    query = 'SELECT domain FROM user WHERE token = ?'
    result = query_db(query, args=(token, ), one=True)
    if not result:
        return False
    domain = '{}.{}'.format(result.get('domain'), DOMAIN)
    return domain

# 检查是否合法类型


def is_valid_type(type):
    return type in ('dns', 'web')


# 生成域名随机前缀
def id_generator(size=8, chars=string.ascii_letters + string.digits):
    return ''.join(random.choice(chars) for _ in xrange(size))

# md5 hash


def md5(s):
    return hashlib.md5(s).hexdigest()

# 子域名处理流程


def save():
    request_host = request.host
    if request_host != DOMAIN and request_host.endswith('.' + DOMAIN):

        domain = '.'.join(request_host.split('.')[-(DOMAIN_COUNT+2):])
        path = request.path
        url = request.url

        x_forwarded_for = request.headers.get('X-Forwarded-For')
        x_real_ip = request.headers.get('X-Real-IP')
        remote_addr = request.remote_addr
        remote_addr = x_real_ip or x_forwarded_for or remote_addr or 'unknown'
        user_agent = request.headers.get('User-Agent')
        date = time.strftime("%Y-%M-%d %X")

        query = "INSERT INTO web (host, domain, path, url, remote_addr, user_agent, date) VALUES (?, ?, ?, ?, ?, ?, ?);"
        result = query_db(query, args=(
            request_host, domain, path, url, remote_addr, user_agent, date))
        g.db.commit()


@app.route('/')
def main():
    return send_from_directory('./templates', 'index.html')


# 登录
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # 检查参数完整性
        if not all([username, password]):
            # if username is None or password is None:
            code = 400
            message = 'invalid request'
            return jsonify(code=code, message=message), code

        # 检查账号密码
        query = 'SELECT * FROM user where username = ? and password = ?'
        result = query_db(query, args=(username, md5(password)), one=True)
        if result:
            code = 200
            message = 'login success'
            token = result.get('token')
            return jsonify(code=code, message=message, result={'token': token})
        else:
            code = 403
            message = 'invalid username or password'
            return jsonify(code=code, message=message), code
    return render_template('login.html')
    return send_from_directory('./templates', 'login.html')


# 注册
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([username, password, confirm_password]):
            code = 400
            message = 'invalid request'
            return jsonify(code=code, message=message), code
        elif password != confirm_password:
            code = 400
            message = 'confirm password error'
            return jsonify(code=code, message=message), code

        # 查询用户是否存在
        query = 'SELECT * FROM user WHERE username = ?'
        result = query_db(query, args=(username, ))
        if len(result):
            code = 400
            message = 'user already exists'
            return jsonify(code=code, message=message), code

        elif not re.match(r'^[a-zA-Z0-9]{2,12}$', username):
            code = 400
            message = 'invalid username (lower case letters and 2-12 length)'
            return jsonify(code=code, message=message)

        # 生成随机域名 token
        domain = id_generator().lower()
        token = id_generator().lower()
        query = 'INSERT INTO user (username, password, token, domain) values (?, ?, ?, ?)'
        result = query_db(query, args=(username, md5(password), token, domain))
        g.db.commit()

        return jsonify(code=200, message='register success', result={'token': token, 'domain': domain})

    return render_template('register.html')

# 根据 域名 类型 获取对应log


def get_log(domain, log_type='dns'):
    query = 'SELECT * FROM {} WHERE domain = ? ORDER BY id DESC'.format(
        log_type)
    result = query_db(query, args=(domain, ))
    return result


@app.route('/web', methods=['GET', 'POST'])
def web():
    token = request.form.get('token') or request.args.get('token')

    domain = get_domain(token)
    if not get_domain(token):
        code = 400
        message = 'invalid token'
        return jsonify(code=code, message=message), code

    result = get_log(domain, 'web')
    return jsonify(result=result)


@app.route('/dns', methods=['GET', 'POST'])
def dns():
    token = request.form.get('token') or request.args.get('token')

    domain = get_domain(token)
    if not get_domain(token):
        code = 400
        message = 'invalid token'
        return jsonify(code=code, message=message), code

    result = get_log(domain, 'dns')
    return jsonify(result=result)


# 删除所有记录
@app.route('/del/<string:log_type>/all', methods=['POST'])
def del_all(log_type):
    token = request.form.get('token')

    # 校验是否合法类型
    if not is_valid_type(log_type):
        code = 400
        message = 'invalid type'
        return jsonify(code=code, message=message), code

    domain = get_domain(token)
    # 校验token
    if not domain:
        code = 400
        message = 'invalid token'
        return jsonify(code=code, message=message), code

    # 删除
    query = 'DELETE FROM {} WHERE domain = ?'.format(log_type)
    result = query_db(query, args=(domain,))
    g.db.commit()
    # 删除
    message = 'delete all {} success'.format(log_type)
    return jsonify(code=200, message=message)

# 检查是否对应token所属域名


def is_owner_domain(log_type, token, log_id):

    domain = get_domain(token)

    # 查询id对应的host
    query = 'SELECT * from {} where id = ?'.format(log_type)
    result = query_db(query, args=(log_id, ), one=True)
    if not result:
        return False
    host = result.get('host') or result.get('qname').rstrip('.')
    if host.endswith(domain):
        return True
    return False

# 删除记录


@app.route('/del/<string:log_type>/<int:log_id>', methods=['POST'])
def del_item(log_type, log_id):
    token = request.form.get('token')

    # 校验类型
    if not is_valid_type(log_type):
        code = 400
        message = 'invalid type'
        return jsonify(code=code, message=message), code
    elif not get_domain(token):
        code = 400
        message = 'invalid token'
        return jsonify(code=code, message=message), code

    sign = is_owner_domain(log_type, token, log_id)
    if not sign:
        code = 400
        message = 'invalid token'
        return jsonify(code=code, message=message), code
    query = 'DELETE FROM {} WHERE id = ?'.format(log_type)
    cur = query_db(query, args=(log_id, ))
    g.db.commit()

    code = 200
    message = 'del item success'
    return jsonify(code=code, message=message), code


@app.route('/user', methods=['POST'])
def user():
    token = request.form.get('token')
    query = 'SELECT token, domain FROM user WHERE token = ?'
    result = query_db(query, args=(token,), one=True)
    if not result:
        code = 404
        message = 'user not found'
        return jsonify(code=code, message=message), code
    domain = '{}.{}'.format(result.get('domain'), DOMAIN)
    token = result.get('token')

    # 查询web记录
    query = 'SELECT * FROM web WHERE domain = ?'
    result = query_db(query, args=(domain, ))
    web_total = len(result) or 0

    # 查询dns记录
    query = 'SELECT * FROM dns WHERE domain = ?'
    result = query_db(query, args=(domain, ))
    dns_total = len(result) or 0

    tpl = 'http://{}/{}?token={}'
    result = {}
    result['dns_api'] = tpl.format(ADMIN_DOMAIN, 'dns', token)
    result['web_api'] = tpl.format(ADMIN_DOMAIN, 'web', token)
    result['domain'] = domain
    result['token'] = token
    result['dns_total'] = dns_total
    result['web_total'] = web_total
    code = 200
    message = 'ok'
    return jsonify(code=code, message=message, result=result)


# 404
@app.errorhandler(404)
def page_not_found(error):
    return jsonify(code=404, message='Not Found'), 404

if __name__ == '__main__':
    app.debug = True
    # app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
    app.run(host='0.0.0.0', port=80, threaded=True)
