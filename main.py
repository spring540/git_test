import socketserver
import os
import sys
import json
import hashlib
from pathlib import Path
import shutil

from Utils.checksum import check_sum, check_sum_file
from Utils.init_server import init_server
from Utils.arr_find_key import arr_find_key

import DAO.op as sql_op

import config

HOST, PORT = "0.0.0.0", 1083
LONG_TIMEOUT = 5
TCP_TIMEOUT = 5


class MyTCPHandler(socketserver.BaseRequestHandler):
    def send_msg(self, msg):
        data_length = len(msg).to_bytes(4, 'little')
        checksum = int(check_sum(msg), 16).to_bytes(16, 'little')
        msg_raw = msg.encode()
        self.request.sendall(data_length)
        self.request.sendall(checksum)
        self.request.sendall(msg_raw)

    def send_file(self, path):
        checksum = check_sum_file(path)
        data_length = str(os.path.getsize(path)).zfill(32).encode()
        flag = str(0).zfill(8).encode()
        self.request.sendall(data_length)
        self.request.sendall(checksum)
        self.request.sendall(flag)
        with open(path, 'rb') as file:
            while True:
                data = file.read(102400)
                if not data:
                    break
                self.request.sendall(data)

    def recv_file(self):
        # 接受协议头
        try:
            data_length = int.from_bytes(self.request.recv(4), byteorder="little")
            checksum = '{:032x}'.format(int.from_bytes(self.request.recv(16), byteorder="little"))
            flag_raw = int.from_bytes(self.request.recv(1), byteorder="little")
        except Exception as e:
            return {
                'type': 999,
                'code': 999,
                'succeed': False,
                'msg': '发生未知错误'
            }

        # 接受文件
        try:
            tmp_file = os.path.join(config.TMP, checksum)
            if os.path.exists(tmp_file):
                # 删除临时文件
                os.remove(tmp_file)
            m = hashlib.md5()
            with open(tmp_file, 'wb') as file:
                has_recv_length = 0
                while has_recv_length < data_length:
                    recv_data = self.request.recv(5120000)
                    has_recv_length += len(recv_data)
                    m.update(recv_data)
                    file.write(recv_data)
            if m.hexdigest() != checksum:
                print('check sum error')
                return {
                    'type': 999,
                    'code': 998,
                    'succeed': False,
                    'msg': 'md5校验失败，数据包损坏'
                }
            else:
                return {
                    'succeed': True,
                    'path': tmp_file
                }
        except Exception as e:
            print(e)
            return {
                'type': 999,
                'code': 999,
                'succeed': False,
                'msg': '发生未知错误'
            }

    def recv_msg(self):
        # 接受协议头
        try:
            data_length = int.from_bytes(self.request.recv(4), byteorder="little")
            checksum = '{:032x}'.format(int.from_bytes(self.request.recv(16), byteorder="little"))
            op = int.from_bytes(self.request.recv(1), byteorder="little")
            flag_raw = int.from_bytes(self.request.recv(1), byteorder="little")
        except Exception as e:
            return {
                'type': 999,
                'code': 999,
                'succeed': False,
                'msg': '发生未知错误'
            }

        # 接受数据
        try:
            has_recv_length = 0
            data = b''
            while has_recv_length < data_length:
                t = self.request.recv(5120000)
                has_recv_length += len(t)
                data += t
            # data = data.decode()
            if check_sum(data) != checksum:
                print(data)
                print('check sum error')
                return {
                    'type': 999,
                    'code': 998,
                    'succeed': False,
                    'msg': 'md5校验失败，数据包损坏'
                }
        except Exception as e:
            print(e)
            return {
                'type': 999,
                'code': 999,
                'succeed': False,
                'msg': '发生未知错误'
            }

        return {
            'succeed': True,
            'data': data,
            'op': op,
            'flag_raw': flag_raw
        }

    def handle(self):
        recv_data = self.recv_msg()
        print(recv_data)
        if recv_data['op'] == 1:
            print('请求目录结构')
            parse_data = json.loads(recv_data['data'])
            sql_data = sql_op.get_user_dir(parse_data['user_id'])
            result = []
            for file_item in sql_data:
                # file_item[0]: path_dir
                # file_item[1]: filename
                # file_item[2]: lasttime
                # file_item[3]: type
                path_parts = Path(
                    os.path.relpath(file_item[0], str(parse_data['user_id']))
                ).parts
                path_parts = [x for x in path_parts]
                parent_dir_arr = result
                parent_dir = ''
                for i in range(len(path_parts)):
                    parent_dir = os.path.join(parent_dir, path_parts[i])
                    index = arr_find_key(parent_dir_arr, 'name', path_parts[i])
                    if index == -1:
                        # 这层目录或者文件没建立
                        parent_dir_arr.append({
                            'name': path_parts[i],
                            'type': 2,
                            'path': parent_dir,
                            'lasttime': 0,
                            'children': []
                        })
                        parent_dir_arr = parent_dir_arr[len(parent_dir_arr) - 1]['children']
                    else:
                        # 已建立该目录，直接递归下去
                        parent_dir_arr = parent_dir_arr[index]['children']

                # 插入最后的文件/文件夹
                if file_item[3] == 2:
                    # 最后插入的是文件夹
                    index = arr_find_key(parent_dir_arr, 'name', file_item[1])
                    if index == -1:
                        parent_dir_arr.append({
                            'name': file_item[1],
                            'type': file_item[3],
                            'lasttime': file_item[2],
                            'path': os.path.join(file_item[0], file_item[1]),
                            'children': []
                        })
                    else:
                        parent_dir_arr[index]['lasttime'] = file_item[2]
                else:
                    # 最后插入的是文件
                    parent_dir_arr.append({
                        'name': file_item[1],
                        'type': file_item[3],
                        'lasttime': file_item[2],
                        'path': os.path.join(file_item[0], file_item[1]),
                        'children': []
                    })
            self.send_msg(json.dumps({
                'succeed': True,
                'code': 100,
                'data': result
            }))

        elif recv_data['op'] == 2:
            print('下载文件')
            parse_data = json.loads(recv_data['data'])
            if 'path' not in parse_data.keys():
                print('没有path参数')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: path'
                }))
            else:
                path = os.path.join(config.data_dir, str(parse_data['user_id']), parse_data['path'])
                if not os.path.exists(path):
                    self.send_msg(json.dumps({
                        'succeed': False,
                        'code': 301,
                        'msg': '文件不存在'
                    }))
                else:
                    self.send_file(path)

        elif recv_data['op'] == 3:
            print('新建文件/文件夹')
            parse_data = json.loads(recv_data['data'])
            if 'name' not in parse_data.keys():
                print('没有name参数')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: name'
                }))
            elif 'dst_path' not in parse_data.keys():
                print('没有dst_path参数')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: dst_path'
                }))
            elif 'type' not in parse_data.keys():
                print('没有type参数')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: type'
                }))
            elif 'updatetime' not in parse_data.keys():
                print('updatetime')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: updatetime'
                }))
            else:
                if parse_data['type'] == 1:
                    # 新建文件
                    print('新建文件')
                    file_dir = os.path.join(
                        config.data_dir, str(parse_data['user_id']), parse_data['dst_path']
                    )
                    file_path = os.path.join(file_dir, parse_data['name'])
                    if os.path.isfile(file_path):
                        # 已存在当前文件
                        self.send_msg(json.dumps({
                            'succeed': False,
                            'code': 601,
                            'msg': '文件已存在'
                        }))
                    else:
                        # 不存在文件，可以新建
                        self.send_msg(json.dumps({
                            'succeed': True,
                            'code': 100,
                            'msg': '可以新建，请发送文件'
                        }))
                        result = self.recv_file()
                        if result['succeed']:
                            # 接受成功
                            if os.path.isdir(file_dir):
                                shutil.move(result['path'], file_path)
                            else:
                                # 文件夹不存在
                                rel_path = os.path.relpath(file_dir, config.data_dir)
                                rel_path = os.path.relpath(rel_path, str(parse_data['user_id']))
                                rel_path_parts = [x for x in Path(rel_path).parts]
                                parent = os.path.join(config.data_dir, str(parse_data['user_id']))
                                for item in rel_path_parts:
                                    t = parent
                                    parent = os.path.join(parent, item)
                                    if not os.path.isdir(parent):
                                        os.mkdir(parent)
                                        sql_op.add_file(
                                            user_id=parse_data['user_id'],
                                            path=os.path.relpath(parent, config.data_dir),
                                            lasttime=0,
                                            filename=item,
                                            path_dir=os.path.join(os.path.relpath(t, config.data_dir), ''),
                                            filetype=2
                                        )

                                # 文件夹创建完毕
                                shutil.move(result['path'], file_path)
                            sql_op.add_file(
                                user_id=parse_data['user_id'],
                                path=os.path.relpath(file_path, config.data_dir),
                                lasttime=parse_data['updatetime'],
                                filename=parse_data['name'],
                                path_dir=os.path.join(os.path.relpath(file_dir, config.data_dir), ''),
                                filetype=1
                            )
                            self.send_msg(json.dumps({
                                'succeed': True,
                                'code': 100,
                                'msg': '创建完成'
                            }))
                        else:
                            # 接受失败
                            self.send_msg(json.dumps(result))

                elif parse_data['type'] == 2:
                    # 新建文件夹
                    print('新建文件夹')
                    file_dir = os.path.join(
                        config.data_dir, str(parse_data['user_id']), parse_data['dst_path']
                    )
                    file_path = os.path.join(file_dir, parse_data['name'])
                    if os.path.isdir(file_path):
                        # 已存在当前文件夹
                        self.send_msg(json.dumps({
                            'succeed': False,
                            'code': 602,
                            'msg': '文件夹已存在'
                        }))
                    else:
                        # 不存在文件夹，可以新建
                        if os.path.isdir(file_dir):
                            os.mkdir(file_path)
                        else:
                            # 父文件夹不存在
                            rel_path = os.path.relpath(file_dir, config.data_dir)
                            rel_path = os.path.relpath(rel_path, str(parse_data['user_id']))
                            rel_path_parts = [x for x in Path(rel_path).parts]
                            parent = os.path.join(config.data_dir, str(parse_data['user_id']))
                            for item in rel_path_parts:
                                t = parent
                                parent = os.path.join(parent, item)
                                if not os.path.isdir(parent):
                                    os.mkdir(parent)
                                    sql_op.add_file(
                                        user_id=parse_data['user_id'],
                                        path=os.path.relpath(parent, config.data_dir),
                                        lasttime=0,
                                        filename=item,
                                        path_dir=os.path.join(os.path.relpath(t, config.data_dir), ''),
                                        filetype=2
                                    )

                            # 文件夹创建完毕
                            os.mkdir(file_path)
                        sql_op.add_file(
                            user_id=parse_data['user_id'],
                            path=os.path.relpath(file_path, config.data_dir),
                            lasttime=parse_data['updatetime'],
                            filename=parse_data['name'],
                            path_dir=os.path.join(os.path.relpath(file_dir, config.data_dir), ''),
                            filetype=2
                        )
                        self.send_msg(json.dumps({
                            'succeed': True,
                            'code': 100,
                            'msg': '创建完成'
                        }))

        elif recv_data['op'] == 4:
            print('删除文件/文件夹')
            parse_data = json.loads(recv_data['data'])
            if 'path' not in parse_data.keys():
                print('没有path参数')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: path'
                }))
            else:
                path = os.path.join(str(parse_data['user_id']), parse_data['path'])
                fullpath = os.path.join(config.data_dir, path)
                sql_data = sql_op.get_file_info(fullpath)
                if not len(sql_data) == 0:
                    self.send_msg(json.dumps({
                        'succeed': False,
                        'code': 501,
                        'msg': '文件不存在'
                    }))
                else:
                    if sql_data[1] == 1:
                        # 文件
                        os.remove(path)
                        result = sql_op.del_file(path)
                        self.send_msg(json.dumps(result))
                    else:
                        # 文件夹
                        try:
                            os.rmdir(fullpath)
                            result = sql_op.del_file(path)
                            self.send_msg(json.dumps(result))
                        except WindowsError as e:
                            if e.errno == 41 and \
                                    'flag' in parse_data.keys() and \
                                    parse_data['flag'] == 1:
                                # 强行删除整个文件夹
                                shutil.rmtree(fullpath)

                            else:
                                self.send_msg(json.dumps({
                                    'succeed': False,
                                    'code': 502,
                                    'msg': '文件夹不为空，无法删除'
                                }))
        elif recv_data['op'] == 5:
            print('更新文件')
            parse_data = json.loads(recv_data['data'])
            if 'filename' not in parse_data.keys():
                print('没有filename参数')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: filename'
                }))
            elif 'dir' not in parse_data.keys():
                print('没有dir参数')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: dir'
                }))
            elif 'lasttime' not in parse_data.keys():
                print('没有lasttime参数')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: lasttime'
                }))
            elif 'updatetime' not in parse_data.keys():
                print('没有updatetime参数')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: updatetime'
                }))
            else:
                file_dir = os.path.join(str(parse_data['user_id']), parse_data['dir'])
                file_path = os.path.join(file_dir, parse_data['filename'])
                sql_data = sql_op.get_file_info(file_path)
                if len(sql_data) == 0:
                    # 没有这个文件
                    self.send_msg(json.dumps({
                        'succeed': False,
                        'code': 701,
                        'msg': '目标文件不存在'
                    }))
                elif sql_data[0][0] != parse_data['lasttime']:
                    # 上一个更新时间戳不相同，文件冲突
                    if 'flag' in parse_data.keys() and parse_data['flag'] == 1:
                        # 强制覆盖
                        self.send_msg(json.dumps({
                            'succeed': True,
                            'code': 101,
                            'msg': '可以更新'
                        }))
                        result = self.recv_file()
                        shutil.move(result['path'], os.path.join(config.ROOT_DIR, file_path))
                        result = sql_op.update_file_time(file_path, parse_data['updatetime'])
                        self.send_msg(json.dumps(result))
                    else:
                        self.send_msg(json.dumps({
                            'succeed': False,
                            'code': 702,
                            'msg': '文件冲突'
                        }))
                else:
                    # 可以更新文件
                    self.send_msg(json.dumps({
                        'succeed': True,
                        'code': 100,
                        'msg': '可以更新'
                    }))
                    result = self.recv_file()
                    shutil.move(result['path'], os.path.join(config.ROOT_DIR, file_path))
                    result = sql_op.update_file_time(file_path, parse_data['updatetime'])
                    self.send_msg(json.dumps(result))
        elif recv_data['op'] == 6:
            print('重命名文件/文件夹')
            parse_data = json.loads(recv_data['data'])
            if 'src_path' not in parse_data.keys():
                print('没有src_path参数')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: src_path'
                }))
            elif 'dst_path' not in parse_data.keys():
                print('没有dst_path参数')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: dst_path'
                }))
            elif 'updatetime' not in parse_data.keys():
                print('没有updatetime参数')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: updatetime'
                }))
            elif 'type' not in parse_data.keys():
                print('没有type参数')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: type'
                }))
            else:
                user_src_path = os.path.join(str(parse_data['user_id']), parse_data['src_path'])
                user_dst_path = os.path.join(str(parse_data['user_id']), parse_data['dst_path'])
                full_src_path = os.path.join(config.data_dir, user_src_path)
                full_dst_path = os.path.join(config.data_dir, user_dst_path)
                dst_dir, dst_name = os.path.split(user_dst_path)
                src_dir, src_name = os.path.split(user_src_path)
                dst_dir = os.path.join(dst_dir, '')
                src_dir = os.path.join(src_dir, '')
                print(os.path.normcase(full_src_path))
                print(os.path.normcase(full_dst_path))
                if os.path.normcase(dst_dir) == os.path.normcase(src_dir):
                    sql_data = sql_op.get_file_info(user_src_path)
                    if len(sql_data) == 0:
                        self.send_msg(json.dumps({
                            'succeed': False,
                            'code': 802,
                            'msg': '源文件/目录不存在'
                        }))
                    else:
                        os.rename(full_src_path, full_dst_path)
                        result = sql_op.rename_file(
                            src=user_src_path,
                            dst_path=user_dst_path,
                            dst_dir=dst_dir,
                            dst_name=dst_name,
                            updatetime=parse_data['updatetime'],
                            filetype=parse_data['type']
                        )
                        self.send_msg(json.dumps(result))
                else:
                    self.send_msg(json.dumps({
                        'succeed': False,
                        'code': 801,
                        'msg': '重命名后的路径不规范'
                    }))

        elif recv_data['op'] == 7:
            print('注册')
            parse_data = json.loads(recv_data['data'])
            if 'username' not in parse_data.keys():
                print('没有username参数')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: password'
                }))
            elif 'password' not in parse_data.keys():
                print('没有password参数')
                self.send_msg(json.dumps({
                    'succeed': False,
                    'code': 200,
                    'msg': '缺少参数: password'
                }))
            else:
                result = sql_op.register(parse_data['username'], parse_data['password'])
                self.send_msg(json.dumps(result))

        else:
            print('异常')

        self.request.close()


def main():
    print('hello world')
    print('init server...')
    config.ROOT_DIR = os.path.dirname(os.path.abspath(__name__))
    err = init_server()
    print(config.data_dir)
    if err:
        print(err)
        sys.exit(1)
    print('init finished. \nstart server...')
    server = socketserver.ThreadingTCPServer(
        (config.HOST, config.PORT), MyTCPHandler)

    # 处理ctrl+c事件
    server.serve_forever()


if __name__ == '__main__':
    main()
