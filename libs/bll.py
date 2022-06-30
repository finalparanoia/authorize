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

from libs.handler.db import DataBaseOperator
from libs.public import get_hash
from pydantic import BaseModel


# 注册检查
class RegisterData(BaseModel):
    name: str = ""
    passwd: str


# 登录检查
class LoginData(BaseModel):
    uid: str
    passwd: str


# 认证检查
class AuthData(BaseModel):
    tmp_uid: str
    token: str


class Bll:
    def __init__(self):
        # 连接数据库
        self.db_op = DataBaseOperator()
        # 执行初始化操作

    # 注册
    def register(self, username: str, passwd: str):
        return {"uid": self.db_op.register(username, passwd)}

    # TODO 公钥认证

    # TODO 2FA认证

    # 密码认证
    def auth_passwd(self, uid: str, passwd: str):
        # 如果存在符合要求的档案，则认证通过
        if not self.db_op.collision_check("db", "auth", {"uid": uid, "passwd": get_hash(passwd)}):
            # 调用生成令牌的方法
            return self.db_op.gen_token(uid)
        # 不通过，返还失败
        else:
            return False

    # 新建令牌
    def get_token(self, uid: str, passwd: str):
        return self.auth_passwd(uid, passwd)

    # 令牌认证
    def auth_token(self, tmp_uid: str, token: str):
        # 检查令牌档案是否存在
        if not self.db_op.collision_check("db", "act_usr", {"tmp_uid": tmp_uid, "token": token}):
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
            self.db_op.revoke_token(tmp_uid, "")
            # 返还完成
            return {"status": 0}
        else:
            # 返还失败
            return False

    def revoke_token_all(self, uid: str, passwd: str):
        # 验证密码
        if self.auth_passwd(uid, passwd):
            # 通过，执行注销全部令牌的方法
            self.db_op.revoke_token("", uid)
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
            self.db_op.auth_delete(uid)
            # 返还成功
            return {"status": 0}
        else:
            # 返还失败
            return False

    # 日志
    def log(self, ip: str, port: int, i_face: str, status: bool):
        profile = {
            "ip": ip,
            "port": port,
            "i_face": i_face,
            "status": status
        }
        self.db_op.log("func", profile)

    # 注入测试
    def exploit(self):
        return self.db_op.exploit()
