from hashlib import sha512
from uuid import uuid4


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
