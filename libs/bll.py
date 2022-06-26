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
    # 如果输入值是字符串类型
    if type(data) == str:
        # 使用utf-8编码为字节
        data = data.encode("utf-8")
    # 实例化一个sha512类
    sha = sha512()
    # 向这个对象输入需要获取哈希的字节
    sha.update(data)
    # 返还哈希
    return sha.hexdigest()


def gen_uid():
    # 返还一个uuid4格式的字符串
    return str(uuid4())


class Bll:
    def __init__(self):
        # 连接数据库
        self.__db__ = Dal()
        # 执行初始化操作
        self.__initialization__()

    # 初始化数据库
    def __initialization__(self):
        # 如果不存在db，就添加管理员档案
        if "db" not in self.__db__.get_db_list():
            profile = {
                "uid": "admin",
                "usr": "admin",
                "passwd": get_hash("admin"),
                "access": "0",
                "otp": "",
                "pub_key": ""}
            self.__db__.add_one("db", "auth", profile)
        # 存在则跳过
        else:
            pass

    # 注册
    def register(self, username: str, passwd: str):
        return {"uid": self.__register__(username, passwd)}

    # TODO 公钥认证

    # TODO 2FA认证

    # 密码认证
    def auth_passwd(self, uid: str, passwd: str):
        # 如果存在符合要求的档案，则认证通过
        if not self.__collision_check__("db", "auth", {"uid": uid, "passwd": get_hash(passwd)}):
            # 调用生成令牌的方法
            return self.__gen_token__(uid)
        # 不通过，返还失败
        else:
            return False

    # 新建令牌
    def get_token(self, uid: str, passwd: str):
        return self.auth_passwd(uid, passwd)

    # 令牌认证
    def auth_token(self, tmp_uid: str, token: str):
        # 检查令牌档案是否存在
        if not self.__collision_check__("db", "act_usr", {"tmp_uid": tmp_uid, "token": token}):
            # 验证无误，返还正常值
            return {"status": 0}
        # 返还失败
        else:
            return False

    # TODO 更新

    # 注销令牌
    def revoke_token_one(self, tmp_uid: str, token: str):
        # 验证令牌是否有效
        if self.auth_token(tmp_uid, token):
            # 有效，则注销令牌
            self.__revoke_token__(tmp_uid, "")
            # 返还完成
            return {"status": 0}
        else:
            # 返还失败
            return False

    def revoke_token_all(self, uid: str, passwd: str):
        # 验证密码
        if self.auth_passwd(uid, passwd):
            # 通过，执行注销全部令牌的方法
            self.__revoke_token__("", uid)
            # 返还成功
            return {"status": 0}
        else:
            # 返还失败
            return False

    # 删除账号
    def auth_delete(self, uid: str, passwd: str):
        # 验证密码是否有效
        if self.auth_passwd(uid, passwd):
            # 有效，执行删除账户的方法
            self.__auth_delete__(uid)
            # 返还成功
            return {"status": 0}
        else:
            # 返还失败
            return False

    # 内部方法

    # 新建账户
    def __register__(self, username: str, passwd: str):
        uid = ""
        while True:
            uid += gen_uid()
            # 确保获得一个没有重复的uid
            if self.__collision_check__("db", "auth", {"uid": uid}):
                # 建立档案
                profile = {
                    "uid": uid,
                    "usr": username,
                    "passwd": get_hash(passwd),
                    "access": "4",
                    "otp": "",
                    "pub_key": ""}
                # 添加档案到数据库
                self.__db__.add_one("db", "auth", profile)
                break
        # 返还uid
        return uid

    # 查询档案
    def __find_profile__(self, db_name: str, col_name: str, data: dict or list):
        return self.__db__.find(db_name, col_name, data)

    # 碰撞检查
    def __collision_check__(self, db_name: str, col_name: str, data: dict or list):
        # 检查符合要求的档案个数，如不为0则至少有一个符合要求的档案
        if len(self.__find_profile__(db_name, col_name, data)) != 0:
            # 碰撞发生，碰撞检查返还失败
            return False
        else:
            # 无碰撞发生，返还成功
            return True

    # 生成令牌
    def __gen_token__(self, uid: str):
        tmp_uid = ""
        while True:
            # 确保生成一个不重复的临时uid
            tmp_uid += gen_uid()
            if self.__collision_check__("db", "act_usr", {"tmp_uid": tmp_uid}):
                # 生成一个安全的随机令牌
                token = token_hex()
                # 将档案添加至数据库
                self.__db__.add_one("db", "act_usr", {"tmp_uid": tmp_uid, "uid": uid, "token": token})
                break
        # 返还档案
        return {"tmp_uid": tmp_uid, "token": token}

    # 注销令牌
    def __revoke_token__(self, tmp_uid: str, uid: str):
        # 根据临时uid撤销令牌
        if tmp_uid != "":
            self.__db__.del_many("db", "act_usr", {"tmp_uid": tmp_uid})
        # 根据uid撤销令牌
        elif uid != "":
            self.__db__.del_many("db", "act_usr", {"uid": uid})
        else:
            # 都不符合，返还失败
            return False
        # 任意一个符合，返还成功
        return True

    # 删除账号
    def __auth_delete__(self, uid: str):
        # 根据uid删除账号档案
        self.__db__.del_many("db", "auth", {"uid": uid})
        # 根据uid撤销依旧有效的令牌
        self.__db__.del_many("db", "act_usr", {"uid": uid})
        return True

    # 注入测试
    def exploit(self):
        # 返还整个数据库的内容，用以模拟遭受注入的场景
        return self.__db__.find("db", "auth", {})
