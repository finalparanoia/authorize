from libs.dal import Dal
from libs.public import get_hash
from secrets import token_hex
from libs.public import gen_uid


class DataBaseOperator:
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

    # 新建账户
    def register(self, username: str, passwd: str):
        uid = ""
        while True:
            uid += gen_uid()
            # 确保获得一个没有重复的uid
            if self.collision_check("db", "auth", {"uid": uid}):
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
    def find_profile(self, db_name: str, col_name: str, data: dict or list):
        return self.__db__.find(db_name, col_name, data)

    # 碰撞检查
    def collision_check(self, db_name: str, col_name: str, data: dict or list):
        # 检查符合要求的档案个数，如不为0则至少有一个符合要求的档案
        if len(self.find_profile(db_name, col_name, data)) != 0:
            # 碰撞发生，碰撞检查返还失败
            return False
        else:
            # 无碰撞发生，返还成功
            return True

    # 生成令牌
    def gen_token(self, uid: str):
        tmp_uid = ""
        while True:
            # 确保生成一个不重复的临时uid
            tmp_uid += gen_uid()
            if self.collision_check("db", "act_usr", {"tmp_uid": tmp_uid}):
                # 生成一个安全的随机令牌
                token = token_hex()
                # 将档案添加至数据库
                self.__db__.add_one("db", "act_usr", {"tmp_uid": tmp_uid, "uid": uid, "token": token})
                break
        # 返还档案
        return {"tmp_uid": tmp_uid, "token": token}

    # 注销令牌
    def revoke_token(self, tmp_uid: str, uid: str):
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
    def auth_delete(self, uid: str):
        # 根据uid删除账号档案
        self.__db__.del_many("db", "auth", {"uid": uid})
        # 根据uid撤销依旧有效的令牌
        self.__db__.del_many("db", "act_usr", {"uid": uid})
        return True

    # 日志
    def log(self, log_type: str, profile: dict):
        self.__db__.add_one("log", log_type, profile)

    # 注入测试
    def exploit(self):
        # 返还整个数据库的内容，用以模拟遭受注入的场景
        return self.__db__.find("db", "auth", {})
