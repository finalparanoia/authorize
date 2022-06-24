from json import dumps
from re import findall
from uvicorn import run
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from libs.bll import Bll

bll = Bll()
app = FastAPI()

origins = [
    "http://localhost:8080",
    "http://localhost",
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 返还结果安全检查
def result_check(data: dict or list or bool):
    str_data = dumps(data)
    if len(findall(r"passw", str_data)) != 0:
        raise HTTPException(status_code=403, detail="Request Forbidden")
        # return data
    elif type(data) == bool:
        raise HTTPException(status_code=403, detail="UnAuthorized")
    else:
        return data


# 状态响应
@app.get("/test/")
async def test():
    return {"status_code": 0}


# 注册检查
class RegisterData(BaseModel):
    name: str = ""
    passwd: str


# 注册接口
@app.post("/register/")
async def register(data: RegisterData):
    return result_check(bll.register(data.name, data.passwd))


# 登录检查
class LoginData(BaseModel):
    uid: str
    passwd: str


# 登录接口
@app.post("/auth/passwd/")
async def auth_passwd(data: LoginData):
    return result_check(bll.get_token(data.uid, data.passwd))


# 认证检查
class AuthData(BaseModel):
    tmp_uid: str
    token: str


# 认证接口
@app.post("/auth/token/")
async def auth_token(data: AuthData):
    return result_check(bll.auth_token(data.tmp_uid, data.token))


# 注销令牌
@app.post("/revoke/tmp_uid/")
async def revoke_one(data: AuthData):
    return result_check(bll.revoke_token_one(data.tmp_uid, data.token))


@app.post("/revoke/uid/")
async def revoke_all(data: LoginData):
    return result_check(bll.revoke_token_all(data.uid, data.passwd))


# 删除账号
@app.post("/delete/")
async def delete(data: LoginData):
    return result_check(bll.auth_delete(data.uid, data.passwd))


# 注入测试
@app.get("/exploit/")
async def exploit():
    return result_check(bll.exploit())


if __name__ == '__main__':
    run(app="main:app", host="0.0.0.0", port=8080, reload=True)
