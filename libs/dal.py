from pymongo import MongoClient


class Dal:
    def __init__(self):
        self.db_conn = MongoClient("mongodb://localhost:27017/")

    # 添加一条记录
    def add_one(self, db: str, col: str, data: list or dict):
        db = self.db_conn[db]
        db_col = db[col]
        db_col.insert_one(data)

    # 条件查询
    def find(self, db: str, col: str, data: list or dict):
        db = self.db_conn[db]
        db_col = db[col]
        result = []
        for item in db_col.find(data):
            item.pop("_id")
            result.append(item)
        return result

    # 条件删除
    def del_many(self, db: str, col: str, data: list or dict):
        db = self.db_conn[db]
        db_col = db[col]
        db_col.delete_many(data)

    # 初始化
    def get_db_list(self):
        return self.db_conn.list_database_names()
