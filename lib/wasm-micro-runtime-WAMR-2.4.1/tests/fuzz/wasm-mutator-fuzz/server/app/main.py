#!/usr/bin/env python
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

# coding=utf-8
from sched import scheduler
from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin
from datetime import datetime, timedelta
from urllib.parse import quote
from pathlib import Path
from flask_caching import Cache
from flask_apscheduler import APScheduler
from zipfile import ZipFile, ZIP_DEFLATED
from io import BytesIO
from multiprocessing import Process

import os
import sys
import copy
import getopt
import signal
import psutil
import shutil
import subprocess


current_dir = Path(__file__).parent.resolve()
wasm_mutator_dir = current_dir.parent.parent
fuzz_dir = wasm_mutator_dir.parent

app = Flask(__name__)

# cors
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

cache = Cache(app, config={'CACHE_TYPE': 'simple'})

scheduler = APScheduler()

# sqlite URI
WIN = sys.platform.startswith('win')

if WIN:
    prefix = 'sqlite:///'
else:
    prefix = 'sqlite:////'


app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', prefix + os.path.join(app.root_path, 'data.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


app.secret_key = os.urandom(12).hex()

db = SQLAlchemy(app)


def to_json(inst, cls):
    ret_dict = {}
    for i in cls.__table__.columns:
        value = getattr(inst, i.name)
        if isinstance(value, datetime):
            value = value.strftime('%Y-%m-%d %H:%M:%S')
        ret_dict[i.name] = value
    return ret_dict


class Fuzzing(db.Model):
    __tablename__ = 'fuzzing_task'
    id = db.Column(db.Integer, autoincrement=True,
                   primary_key=True, nullable=False)
    repo = db.Column(db.String(200), nullable=False, default='')
    branch = db.Column(db.String(200), nullable=False, default='')
    build_args = db.Column(db.String(200), nullable=False, default='')
    fuzz_time = db.Column(db.Integer, default=0)
    wamr_commit = db.Column(
        db.String(200), nullable=False, default='')
    data = db.Column(db.JSON)
    start_time = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow() + timedelta(hours=8))
    end_time = db.Column(db.DateTime)
    status = db.Column(db.Integer, default=2)

    @property
    def serialize(self):
        return to_json(self, self.__class__)


class TaskError(db.Model):
    __tablename__ = 'task_error'
    id = db.Column(db.Integer, autoincrement=True,
                   primary_key=True, nullable=False)
    fuzzing_id = db.Column(db.Integer, db.ForeignKey("fuzzing_task.id"))
    name = db.Column(db.String(200), nullable=False, default='')
    std_out = db.Column(db.Text, default='')
    data = db.Column(db.JSON)
    comment = db.Column(db.JSON)
    create_time = db.Column(db.DateTime, nullable=False,
                            default=datetime.utcnow() + timedelta(hours=8))
    update_time = db.Column(db.DateTime, nullable=False,
                            default=datetime.utcnow() + timedelta(hours=8))
    status = db.Column(db.Integer, default=1)

    @property
    def serialize(self):
        return to_json(self, self.__class__)


def to_data(data):
    data['data']['id'] = data['id']
    return data['data']


def error_count(data):
    error = len(TaskError.query.filter(
        TaskError.fuzzing_id == data.get('id'), TaskError.status.in_([1, 2])).all())
    end_error = len(TaskError.query.filter(
        TaskError.fuzzing_id == data.get('id'), TaskError.status == 0).all())
    data['error'] = error
    data['end_error'] = end_error
    return data


def getstatusoutput(cmd):

    try:
        data = subprocess.check_output(
            cmd, shell=True, text=True, stderr=subprocess.STDOUT, executable='/bin/bash')
        exitcode = 0
    except subprocess.CalledProcessError as ex:
        data = ex.output
        exitcode = ex.returncode
    if data[-1:] == '\n':
        data = data[:-1]
    return exitcode, data


def get_wamr_commit(repo_root_dir):

    wamr_repo_dir = repo_root_dir / 'wamr'
    cmd = f'cd {wamr_repo_dir} && git log -1 --pretty=format:"%h"'
    status, resp = getstatusoutput(cmd)

    if status != 0:
        return "-"
    return resp


@app.route('/get_list', methods=["GET"])
@cross_origin()
def show_fuzz_list():
    data = request.args
    id = data.get('id')
    if id:
        all_error = TaskError.query.filter(
            TaskError.fuzzing_id == id).with_entities(TaskError.id, TaskError.fuzzing_id,
                                                      TaskError.create_time, TaskError.data,
                                                      TaskError.name, TaskError.status,
                                                      TaskError.update_time, TaskError.comment).order_by(TaskError.status.desc(), TaskError.update_time.desc(), TaskError.id.desc()).all()
        data_message = [{'id': error['id'], "fuzzing_id": error['fuzzing_id'],
                         "name": error['name'], "data": error['data'],
                         'create_time': error['create_time'].strftime('%Y-%m-%d %H:%M:%S'),
                         'update_time': error['update_time'].strftime('%Y-%m-%d %H:%M:%S'),
                         'status': error['status'], "comment": error["comment"]} for error in all_error]
        return jsonify({"status": 1, "results": data_message, 'msg': "success", "count": len(data_message)})
    else:
        all_fuzz = Fuzzing.query.order_by(
            Fuzzing.status.desc(), Fuzzing.end_time.desc(), Fuzzing.id.desc()).all()
        data_message = list(map(lambda i: i.serialize, all_fuzz))
        data_message = list(map(error_count, data_message))
        return jsonify({"status": 1, "results": data_message, 'msg': "success", "count": len(data_message)})


@app.route('/new_fuzzing', methods=["POST"])
@cross_origin()
def New_fuzzing():
    data = request.json
    repo = data.get('repo', '')
    branch = data.get('branch', '')
    build_args = data.get('build_args', '')
    fuzz_time = data.get('fuzz_time', 0)
    if not repo or not branch:
        return jsonify({"status": 0, "result": "", 'msg': "repo and branch are required !"})

    fuzz = Fuzzing(repo=repo, branch=branch,
                   build_args=build_args, fuzz_time=fuzz_time, start_time=datetime.utcnow() + timedelta(hours=8))
    db.session.add(fuzz)
    db.session.commit()
    fuzz_cmd = wasm_mutator_dir / \
        'workspace' / f'build_{fuzz.id}'
    Path(fuzz_cmd).mkdir(exist_ok=True)

    os.system(
        f'cd {fuzz_cmd} && git clone --branch {branch} --depth=1 {repo} wamr')

    if not Path(fuzz_cmd / 'wamr').exists():
        print('------ error: clone repo not folder exists ------')
        # curd.set_error_status_to(list(map(lambda x: x.id, error_list)), db)
        # Fuzzing.query.filter_by(id=fuzz.id).delete()
        fuzz.data = {'error': "Clone repo Error"}
        db.session.commit()
        return jsonify({"status": 0, "result": "", "msg": "Clone repo Error"})

    wamr_path_parent = fuzz_dir.parent.parent
    wamr_path = wamr_path_parent / 'wamr'
    wamr_path_to = wamr_path_parent / f'wamr_{fuzz.id}'
    wamr_folder = Path(wamr_path).exists()
    try:
        if wamr_folder:
            os.rename(wamr_path, wamr_path_to)
    except Exception as e:
        print(f'------ error: fail wamr folder rename, error: {e} ------')
        return jsonify({"status": 0, "result": "", "msg": "fail wamr folder rename"})
    try:
        os.system(f'ln -s {fuzz_cmd / "wamr"} {wamr_path_parent}')
    except Exception as e:
        print('------ error: fail wamr_repo to wamr ------')
        if wamr_folder:
            os.rename(wamr_path_to, wamr_path)
        return jsonify({"status": 0, "result": "", "msg": "fail wamr_repo to wamr"})
    os.system(
        f'cd {fuzz_cmd} && cmake .. -DCUSTOM_MUTATOR=1 {build_args} && make -j$(nproc)')
    os.system(f'rm -rf {wamr_path}')
    if wamr_folder:
        os.rename(wamr_path_to, wamr_path)
    os.system(
        f"ln -s {wasm_mutator_dir / 'build' / 'CORPUS_DIR'} {fuzz_cmd}")
    cmd_max_time = ''
    if fuzz_time != 0:
        cmd_max_time = f"-max_total_time={fuzz_time}"
    cmd = f'cd {fuzz_cmd} && ./wasm_mutator_fuzz CORPUS_DIR {cmd_max_time} -ignore_crashes=1 -fork=2'
    process_tcpdump = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
    commit_id = get_wamr_commit(fuzz_cmd)
    fuzz.data = {"pid": process_tcpdump.pid}
    fuzz.status = 1
    fuzz.wamr_commit = commit_id
    db.session.commit()
    return jsonify({'status': 1, 'msg': 'success', 'result': ''})


@app.route('/end_fuzzing', methods=["POST"])
@cross_origin()
def End_fuzzing():
    data = request.json
    id = data.get('id')
    if not id:
        return jsonify({'status': 0, 'msg': 'id must pass'})
    fuzz_model = Fuzzing.query.get(id)
    pid = fuzz_model.data.get('pid')
    try:
        os.killpg(pid, signal.SIGTERM)
    except Exception as e:
        pass
    fuzz_model.status = 0
    fuzz_model.end_time = datetime.utcnow() + timedelta(hours=8)
    db.session.commit()
    return jsonify({'status': 1, 'msg': 'success'})


@scheduler.task('interval', id="run_task", seconds=5, misfire_grace_time=60)
def scheduler_run_task():
    fuzz_query = Fuzzing.query.filter(Fuzzing.status == 1).all()
    for fuzz in fuzz_query:
        # if fuzz.fuzz_time == 0:
        #     continue
        if fuzz.data.get('pid', 0) not in psutil.pids() or psutil.Process(fuzz.data.get('pid', 0)).status() == "zombie":
            fuzz.status = 0
            fuzz.end_time = datetime.utcnow() + timedelta(hours=8)
            db.session.commit()

    for fuzz in fuzz_query:
        all_error = TaskError.query.filter(
            TaskError.fuzzing_id == fuzz.id).with_entities(TaskError.name).all()
        fuzz_cmd = wasm_mutator_dir / \
            'workspace' / f'build_{fuzz.id}'
        dir_list = filter(lambda x: x.startswith(
            'crash-') or x.startswith('oom-') or x.startswith('slow-unit-') or x.startswith('leak-'), os.listdir(fuzz_cmd))
        all_error = [error['name'] for error in all_error]
        dir_list = list(filter(lambda x: x not in all_error, dir_list))
        for dir in dir_list:
            cmd = f'cd {fuzz_cmd} && ./wasm_mutator_fuzz {dir}'
            status, resp = getstatusoutput(cmd)
            task_error = TaskError(name=dir, std_out=resp, fuzzing_id=fuzz.id,
                                   create_time=datetime.utcnow() + timedelta(hours=8))
            db.session.add(task_error)
            db.session.commit()


@app.route("/get_error_out", methods=["GET"])
def get_error_out():
    data = request.args
    id = data.get('id')
    if id:
        error = TaskError.query.get(id)
        data_message = error.serialize
        return jsonify({"status": 1, "result": data_message, 'msg': "success"})
    return jsonify({"status": 0, "results": [], 'msg': "Error"})


@app.route("/get_error_txt", methods=["GET"])
def get_error_txt():
    data = request.args
    id = data.get('id')
    if not id:
        return jsonify({"status": 0, "results": [], 'msg': "Error"})
    error = TaskError.query.get(id)
    fuzz_cmd = wasm_mutator_dir / \
        'workspace' / f'build_{error.fuzzing_id}'
    file_cmd = fuzz_cmd / error.name

    response = send_file(file_cmd, as_attachment=True,
                         attachment_filename=error.name)

    response.headers['Content-Disposition'] += "; filename*=utf-8''{}".format(
        error.name)

    return response


@app.route("/set_commend", methods=["POST"])
def set_commend():
    data = request.json
    id = data.get('id')
    comment = data.get('comment')
    if not id:
        return jsonify({"status": 0, "results": [], 'msg': "Error"})
    try:
        TaskError.query.filter(TaskError.id.in_(
            id)).update({"comment": comment, "update_time": datetime.utcnow() + timedelta(hours=8)})
        db.session.commit()
    except Exception as e:
        return jsonify({"status": 0, "results": [], 'msg': "Update error"})

    return jsonify({"status": 1, "results": [], 'msg': "Success"})


@app.route("/get_cases_zip", methods=["POST"])
def get_cases_zip():
    data = request.json
    id_list = data.get('id')
    task_query = TaskError.query.filter(TaskError.id.in_(id_list)).all()

    memory_file = BytesIO()
    with ZipFile(memory_file, "w", ZIP_DEFLATED) as zf:
        for task_error in task_query:
            fuzz_cmd = wasm_mutator_dir / \
                'workspace' / f'build_{task_error.fuzzing_id}'
            file_cmd = fuzz_cmd / task_error.name
            zf.write(str(file_cmd), arcname=task_error.name)
    memory_file.seek(0)
    return send_file(memory_file, attachment_filename='cases.zip', as_attachment=True)


class processClass:

    def __init__(self, fuzz_cmd, restart_cmd, error_query):
        p = Process(target=self.run, args=(fuzz_cmd, restart_cmd, error_query))
        p.daemon = True                       # Daemonize it
        p.start()                             # Start the execution

    def run(self, fuzz_cmd, restart_cmd, error_query):
        for error in error_query:
            shutil.copyfile(fuzz_cmd / error.name, restart_cmd / error.name)
            commit = get_wamr_commit(restart_cmd)
            cmd = f"cd {restart_cmd} && ./wasm_mutator_fuzz {error.name}"
            status, resp = getstatusoutput(cmd)
            data = copy.deepcopy(error.data)
            if type(data) == dict:
                data['wamr_commit'] = commit
            else:
                data = {'wamr_commit': commit}
            error.data = data
            error.status = 0 if status == 0 else 1
            error.update_time = datetime.utcnow() + timedelta(hours=8)
            error.std_out = resp if status != 0 else error.std_out
            db.session.commit()

        #
        # This might take several minutes to complete


@app.route("/error_restart", methods=["POST"])
def error_restart():
    data = request.json
    id_list = data.get('id')
    repo = data.get('repo')
    branch = data.get('branch')
    build_args = data.get('build_args', '')
    if len(id_list) == [] or repo == "":
        return jsonify({"status": 0, "msg": 'parameter is incorrect'})
    run_status = cache.get('runStatus')
    if run_status:
        return jsonify({"status": 0, "results": [], 'msg': "There are already tasks in progress"})
    task_query = TaskError.query.filter(TaskError.id.in_(id_list)).all()
    fuzzing_id = task_query[0].fuzzing_id
    fuzz_cmd = wasm_mutator_dir / \
        'workspace' / f'build_{fuzzing_id}'
    restart_cmd = wasm_mutator_dir / \
        'workspace' / f'error_restart_build_{fuzzing_id}'
    if not Path(restart_cmd).exists():
        Path(restart_cmd).mkdir(exist_ok=True)
    os.system(
        f'cd {restart_cmd} && git clone --branch {branch} --depth=1 {repo} wamr')

    if not Path(restart_cmd / 'wamr').exists():
        print('------ error: clone repo not folder exists ------')
        # fuzz.data = {'error': "Clone repo Error"}
        db.session.commit()
        return jsonify({"status": 0, "result": "", "msg": "Clone repo Error"})
    wamr_path_parent = fuzz_dir.parent.parent
    wamr_path = wamr_path_parent / 'wamr'
    wamr_path_to = wamr_path_parent / f'wamr_restart_{fuzzing_id}'
    wamr_folder = Path(wamr_path).exists()
    try:
        if wamr_folder:
            os.rename(wamr_path, wamr_path_to)
    except Exception as e:
        print(f'------ error: fail wamr folder rename, error: {e} ------')
        return jsonify({"status": 0, "result": "", "msg": "fail wamr folder rename"})
    try:
        os.system(f'ln -s {restart_cmd / "wamr"} {wamr_path_parent}')
    except Exception as e:
        print('------ error: fail wamr_repo to wamr ------')
        if wamr_folder:
            os.rename(wamr_path_to, wamr_path)
        return jsonify({"status": 0, "result": "", "msg": "fail wamr_repo to wamr"})
    os.system(
        f'cd {restart_cmd} && cmake .. -DCUSTOM_MUTATOR=1 {build_args} && make -j$(nproc)')
    os.system(f'rm -rf {wamr_path}')
    if wamr_folder:
        os.rename(wamr_path_to, wamr_path)
    cache.delete('runStatus')
    TaskError.query.filter(TaskError.id.in_(id_list)).update(
        {'status': 2, "update_time": datetime.utcnow() + timedelta(hours=8)})
    db.session.commit()
    processClass(fuzz_cmd, restart_cmd, task_query)
    return jsonify({"status": 1, "result": "", "msg": "Pending"})


@app.route('/upload_case', methods=['POST'])
def do_upload():
    file = request.files['file']
    filename = file.filename
    upload_file_cmd = wasm_mutator_dir / "upload_path"
    build_cmd = wasm_mutator_dir / "build" / "CORPUS_DIR"
    if not Path(upload_file_cmd).exists():
        Path(upload_file_cmd).mkdir(exist_ok=True)
    file.save(str(upload_file_cmd / filename))
    file.save(str(build_cmd / filename))
    # os.system(f"copy {upload_file_cmd / file} {build_cmd / file}")
    return jsonify({"status": 1, "result": "", "msg": "success"})


@app.route('/remove_case', methods=['POST'])
def remove_case():
    file = request.json
    filename = file.get('filename')
    print(filename)
    upload_file_cmd = wasm_mutator_dir / "upload_path" / filename
    build_cmd = wasm_mutator_dir / "build" / "CORPUS_DIR" / filename
    os.system(f'rm -rf "{upload_file_cmd}" "{build_cmd}"')
    return jsonify({"status": 1, "result": "", "msg": "success"})


if __name__ == '__main__':

    scheduler.init_app(app)
    scheduler.start()
    os.chdir(wasm_mutator_dir)
    os.system('./smith_wasm.sh 100')
    os.chdir(current_dir)
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hp:d:", [
                                   "help", "port=", "debug="])
    except getopt.GetoptError:
        print(
            'test_arg.py -h <host> -p <port> -d <debug? True: False>')
        print(
            '   or: test_arg.py --host=<host> --port=<port> --debug=<True: False>')
        print('''    
        host: default[0.0.0.0]
        port: default[16667]
        debug: default[False]
                    ''')
        sys.exit(2)

    run_dict = {
        "host": "0.0.0.0",
        "port": 16667,
        "debug": False
    }
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(
                'test_arg.py -h <host> -p <port> -d <debug? True: False>')
            print(
                '   or: test_arg.py --host=<host> --port=<port> --debug=<True: False>')
            print('''    
        host: default[0.0.0.0]
        port: default[16667]
        debug: default[False]
                    ''')
            sys.exit()
        elif opt in ('-h', '--host'):
            run_dict['host'] = arg
        elif opt in ("-p", "--port"):
            run_dict['port'] = int(arg)
        elif opt in ("-d", "--debug"):
            run_dict['debug'] = bool(arg)

    app.run(**run_dict)
