import unittest
from secrets import token_hex

from fastapi import HTTPException

from main import result_check
from libs.bll import get_hash, gen_uid, Bll
from HwTestReport import HTMLTestReport


class Request:
    class Client:
        def __init__(self):
            self.host = "127.0.0.1"
            self.port = 2333

    def __init__(self):
        self.client = self.Client()
        self.base_url = "test_url_233"


r = Request()
bll = Bll()


class TestHAPIFunc(unittest.TestCase):

    def setUp(self) -> None:
        pass

    def tearDown(self) -> None:
        pass

    def test_result_check(self):
        self.assertRaises(HTTPException, result_check, r, {"passwd": "23352523"})
        self.assertRaises(HTTPException, result_check, r, False)
        self.assertEqual({}, result_check(r, {}))
        self.assertEqual({"23": 23333}, result_check(r, {"23": 23333}))
        self.assertEqual({"23": "qws"}, result_check(r, {"23": "qws"}))
        self.assertNotEqual({"23": "hello"}, result_check(r, {"23": "hi"}))


class TestBLLFunc(unittest.TestCase):

    def setUp(self) -> None:
        pass

    def tearDown(self) -> None:
        pass

    def test_get_hash(self):
        self.assertEqual("7e7a9b1a170043d1cc491b494b21c9c6" +
                         "dbcfc417d38376cf3e692216cdfaf85c" +
                         "70ab4071eab3e3fbc52e7ae0f211b313" +
                         "8eb415d6954c5b4b5ec21802b59e836b", get_hash("ycy"))
        self.assertNotEqual("団長！車の用意できました！", get_hash("なんか静かですね"))

    def test_gen_uid(self):
        self.assertEqual(str, type(gen_uid()))

    def test_register(self):
        self.assertIn("uid", bll.register("", token_hex()))
        self.assertRaises(TypeError, bll.register, None, None)

    def test_auth_passwd(self):
        self.assertEqual(False, bll.auth_passwd("", ""))
        self.assertEqual(False, bll.auth_passwd("114514", "23333"))
        self.assertIn("tmp_uid" and "token", bll.auth_passwd("admin", "admin"))

    def test_get_token(self):
        self.assertEqual(False, bll.auth_passwd("", ""))
        self.assertEqual(False, bll.auth_passwd("114514", "23333"))
        self.assertIn("tmp_uid" and "token", bll.auth_passwd("admin", "admin"))

    def test_auth_token(self):
        self.assertEqual(False, bll.auth_token("", ""))

    def test_revoke_token_one(self):
        pass

    def test_revoke_token_all(self):
        self.assertEqual(False, bll.auth_passwd("", ""))
        self.assertEqual(False, bll.auth_passwd("114514", "23333"))
        self.assertIn("tmp_uid" and "token", bll.auth_passwd("admin", "admin"))

    def test_auth_delete(self):
        self.assertEqual(False, bll.auth_passwd("", ""))
        self.assertEqual(False, bll.auth_passwd("114514", "23333"))

    def test_log(self):
        pass

    def test_exploit(self):
        self.assertEqual(list, type(bll.exploit()))

    def test___register__(self):
        self.assertIn("uid", bll.register("", token_hex()))
        self.assertRaises(TypeError, bll.register, None, None)

    def test__find_profile__(self):
        self.assertEqual(1, len(bll.__find_profile__("db", "auth", {"uid": "admin"})))

    def test___collision_check__(self):
        self.assertEqual(True, bll.__collision_check__("db", "auth", {"2333": "114514"}))
        self.assertEqual(False, bll.__collision_check__("db", "auth", {"uid": "admin"}))

    def test____gen_token__(self):
        self.assertIn("tmp_uid" and "token", bll.__gen_token__("admin"))

    def test___revoke_token__(self):
        self.assertEqual(False, bll.__revoke_token__("", ""))
        self.assertEqual(True, bll.__revoke_token__("sss", "aaa"))
        self.assertEqual(True, bll.__revoke_token__("", "admin"))

    def test___auth_delete__(self):
        self.assertEqual(True, bll.__auth_delete__(""))


if __name__ == "__main__":
    # unittest.main()
    suite_http_api = unittest.TestLoader().loadTestsFromTestCase(TestHAPIFunc)
    suite_bll = unittest.TestLoader().loadTestsFromTestCase(TestBLLFunc)
    suites = unittest.TestSuite()
    suites.addTests([suite_http_api, suite_bll])
    with open('./HwTestReportIMG.html', 'wb') as report:
        runner = HTMLTestReport(
            stream=report,
            verbosity=2,
            images=True,
            title='授权平台 测试',
            description='详情',
            tester='Johnny')
