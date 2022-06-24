# 0 超级管理员
# 1 系统管理员
# 2 后台管理员
# 3 区块管理员
# 4 用户
# 5 临时用户

# 已完成功能：
# 账号注册
# 账号登录
# 生成令牌
# 令牌认证
# 注销令牌
# 删除账号

from secrets import token_hex
from uuid import uuid4
from libs.dal import Dal
from hashlib import sha512


def get_hash(data: bytes or str):
    if type(data) == str:
        data = data.encode("utf-8")
    sha = sha512()
    sha.update(data)
    return sha.hexdigest()


def gen_uid():
    return str(uuid4())


class Bll:
    def __init__(self):
        self.__db__ = Dal()
        self.__initialization__()

    # 初始化数据库
    def __initialization__(self):
        if "db" not in self.__db__.get_db_list():
            profile = {
                "uid": "admin",
                "usr": "admin",
                "passwd": get_hash("admin"),
                "access": "0",
                "otp": "",
                "pub_key": ""}
            self.__db__.add_one("db", "auth", profile)
        else:
            pass

    # 注册
    def register(self, username: str, passwd: str):
        return {"uid": self.__register__(username, passwd)}

    # TODO 公钥认证

    # TODO 2FA认证

    # 密码认证
    def auth_passwd(self, uid: str, passwd: str):
        if not self.__collision_check__("db", "auth", {"uid": uid, "passwd": get_hash(passwd)}):
            return self.__gen_token__(uid)
        else:
            return False

    # 新建令牌
    def get_token(self, uid: str, passwd: str):
        return self.auth_passwd(uid, passwd)

    # 令牌认证
    def auth_token(self, tmp_uid: str, token: str):
        if not self.__collision_check__("db", "act_usr", {"tmp_uid": tmp_uid, "token": token}):
            return {"status": 0}
        else:
            return False

    # TODO 更新

    # 注销令牌
    def revoke_token_one(self, tmp_uid: str, token: str):
        if self.auth_token(tmp_uid, token):
            self.__revoke_token__(tmp_uid, "")
            return {"status": 0}
        else:
            return False

    def revoke_token_all(self, uid: str, passwd: str):
        if self.auth_passwd(uid, passwd):
            self.__revoke_token__("", uid)
            return {"status": 0}
        else:
            return False

    # 删除账号
    def auth_delete(self, uid: str, passwd: str):
        if self.auth_passwd(uid, passwd):
            self.__auth_delete__(uid)
            return {"status": 0}
        else:
            return False

    # 内部方法

    # 新建账户
    def __register__(self, username: str, passwd: str):
        uid = ""
        while True:
            uid += gen_uid()
            if self.__collision_check__("db", "auth", {"uid": uid}):
                profile = {
                    "uid": uid,
                    "usr": username,
                    "passwd": get_hash(passwd),
                    "access": "4",
                    "otp": "",
                    "pub_key": ""}
                self.__db__.add_one("db", "auth", profile)
                break
        return uid

    # 查询档案
    def __find_profile__(self, db_name: str, col_name: str, data: dict or list):
        return self.__db__.find(db_name, col_name, data)

    # 碰撞检查
    def __collision_check__(self, db_name: str, col_name: str, data: dict or list):
        if len(self.__find_profile__(db_name, col_name, data)) != 0:
            return False
        else:
            return True

    # 生成令牌
    def __gen_token__(self, uid: str):
        tmp_uid = ""
        while True:
            tmp_uid += gen_uid()
            if self.__collision_check__("db", "act_usr", {"tmp_uid": tmp_uid}):
                token = token_hex()
                self.__db__.add_one("db", "act_usr", {"tmp_uid": tmp_uid, "uid": uid, "token": token})
                break
        return {"tmp_uid": tmp_uid, "token": token}

    # 注销令牌
    def __revoke_token__(self, tmp_uid: str, uid: str):
        if tmp_uid != "":
            self.__db__.del_many("db", "act_usr", {"tmp_uid": tmp_uid})
        elif uid != "":
            self.__db__.del_many("db", "act_usr", {"uid": uid})
        else:
            return False
        return True

    # 删除账号
    def __auth_delete__(self, uid: str):
        self.__db__.del_many("db", "auth", {"uid": uid})
        self.__db__.del_many("db", "act_usr", {"uid": uid})
        return True

    # 注入测试
    def exploit(self):
        return self.__db__.find("db", "auth", {})
