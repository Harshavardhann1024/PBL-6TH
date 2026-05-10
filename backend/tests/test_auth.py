from tests.support import ShadowTraceDBTestCase


class AuthenticationTests(ShadowTraceDBTestCase):
    def test_register_login_and_current_user(self) -> None:
        user = self.register_user(email="admin@test.com")
        self.assertEqual(user.email, "admin@test.com")

        token_response = self.login("admin@test.com")
        self.assertTrue(token_response.access_token)

        me = self.db.get(type(user), user.id)
        self.assertIsNotNone(me)
        self.assertEqual(me.email, "admin@test.com")
        self.assertEqual(me.role.value, "admin")
