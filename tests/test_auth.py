import unittest
from datetime import timezone
from sentinelforge.auth.passwords import hash_password, verify_password
from sentinelforge.auth.service import AuthService, AuthenticationError, LastAdminError
from sentinelforge.storage import Database

class AuthTests(unittest.TestCase):
    def test_password_hashing(self):
        first = hash_password("correct horse battery")
        second = hash_password("correct horse battery")
        self.assertNotEqual(first, second)
        self.assertTrue(verify_password("correct horse battery", first))
        self.assertFalse(verify_password("wrong password", first))
        self.assertFalse(verify_password("x", "malformed"))

    def test_user_session_and_final_admin(self):
        with Database() as db:
            auth = AuthService(db)
            user = auth.create_user("admin_user", "correct horse battery", "admin")
            logged, session, token = auth.authenticate("admin_user", "correct horse battery")
            self.assertEqual(logged.user_id, user.user_id)
            self.assertIsNotNone(auth.resolve(token))
            self.assertTrue(auth.csrf_valid(session, session.csrf_token))
            with self.assertRaises(LastAdminError): auth.delete_user(user.user_id)
            auth.revoke(token)
            self.assertIsNone(auth.resolve(token))

    def test_invalid_authentication(self):
        with Database() as db:
            auth = AuthService(db)
            auth.create_user("analyst_user", "correct horse battery", "analyst")
            with self.assertRaises(AuthenticationError): auth.authenticate("analyst_user", "wrong password")

if __name__ == "__main__": unittest.main()
