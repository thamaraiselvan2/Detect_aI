"""Registration uniqueness, deletion and shared-email regression tests.

Email is patched at the monitor_routes -> send_impersonation_email boundary, so no
SMTP connection is made and no credential is required.
"""
import os
import sqlite3
import tempfile
import unittest
import uuid
from unittest.mock import patch

os.environ.update({"MAIL_HOST": "", "MAIL_USERNAME": "", "MAIL_PASSWORD": "", "MAIL_FROM": ""})

import config
import database
from app import app
from database import execute_db, query_db, init_db
from routes import monitor_routes

PIXEL = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="
BIO = "Official account. Software engineer and photographer from Chennai. Business enquiries via DM."


def _tag():
    return uuid.uuid4().hex[:6]


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.usernames = []

    def tearDown(self):
        for name in self.usernames:
            execute_db("DELETE FROM alerts WHERE protected_profile_id IN (SELECT id FROM protected_profiles WHERE LOWER(username)=LOWER(?))", (name,))
            execute_db("DELETE FROM alerts WHERE demo_profile_id IN (SELECT id FROM demo_profiles WHERE LOWER(username)=LOWER(?))", (name,))
            execute_db("DELETE FROM protected_profiles WHERE LOWER(username)=LOWER(?)", (name,))
            execute_db("DELETE FROM registered_profiles WHERE LOWER(username)=LOWER(?)", (name,))
            execute_db("DELETE FROM demo_profiles WHERE LOWER(username)=LOWER(?)", (name,))

    def _demo(self, username):
        self.usernames.append(username)
        execute_db("INSERT INTO demo_profiles (username, display_name, bio, followers_count, account_age_days) VALUES (?, ?, ?, 5000, 900)",
                   (username, username, BIO))

    def _register(self, username, email):
        return self.client.post("/api/register-user", json={"username": username, "email": email})

    def _social_signup(self, username, bio=BIO):
        self.usernames.append(username)
        return self.client.post("/api/social/create-account", json={
            "username": username, "password": "Pass-1234", "bio": bio, "profile_picture": PIXEL})

    # TEST 1
    def test_same_email_different_usernames(self):
        t = _tag()
        for n in ("testuserA", "testuserB", "testuserC"):
            self._demo(f"{n}_{t}")
            r = self._register(f"{n}_{t}", "shared-test@example.com")
            self.assertEqual(r.status_code, 201, r.get_json())
        rows = query_db("SELECT id FROM protected_profiles WHERE email = ? AND username LIKE ?", ("shared-test@example.com", f"%_{t}"))
        self.assertEqual(len(rows), 3)

    # TEST 2
    def test_same_username_rejected(self):
        u = f"testuserA_{_tag()}"
        self._demo(u)
        self.assertEqual(self._register(u, "shared-test@example.com").status_code, 201)
        for email in ("another@example.com", "shared-test@example.com"):
            r = self._register(u, email)
            self.assertEqual(r.status_code, 409)
            self.assertEqual(r.get_json()["reason"], "username_already_registered")
        r = self._register(u.upper(), "x@example.com")  # case-insensitive
        self.assertEqual(r.status_code, 409)

    # TEST 3 (via the app's delete endpoint)
    def test_delete_and_reregister_via_api(self):
        u = f"delete-test-user-{_tag()}"
        self._demo(u)
        r = self._register(u, "delete-test@example.com")
        self.assertEqual(r.status_code, 201)
        pid = r.get_json()["protected_profile_id"]
        self.assertEqual(self.client.delete(f"/api/protected-users/{pid}").status_code, 200)
        self.assertIsNone(query_db("SELECT id FROM protected_profiles WHERE username=?", (u,), one=True))
        self.assertIsNone(query_db("SELECT id FROM registered_profiles WHERE username=?", (u,), one=True))
        r = self._register(u, "new-delete-test@example.com")
        self.assertEqual(r.status_code, 201, r.get_json())
        self.assertEqual(query_db("SELECT email FROM protected_profiles WHERE username=?", (u,), one=True)["email"],
                         "new-delete-test@example.com")

    def test_reregister_after_manual_delete_and_restart(self):
        """Manual delete of protected_profiles only (old orphan state) + restart must not resurrect."""
        u = f"delete-test-user-{_tag()}"
        self._demo(u)
        self.assertEqual(self._register(u, "delete-test@example.com").status_code, 201)
        execute_db("DELETE FROM protected_profiles WHERE username=?", (u,))  # leaves legacy orphan
        init_db()  # simulate Flask restart
        self.assertIsNone(query_db("SELECT id FROM protected_profiles WHERE username=?", (u,), one=True))
        r = self._register(u, "new-delete-test@example.com")
        self.assertEqual(r.status_code, 201, r.get_json())
        self.assertEqual(len(query_db("SELECT id FROM registered_profiles WHERE username=?", (u,))), 1)

    def test_delete_unknown_id_is_404(self):
        self.assertEqual(self.client.delete("/api/protected-users/999999999").status_code, 404)

    # TEST 4 + TEST 5
    @patch.object(monitor_routes, "send_impersonation_email", return_value={"sent": True, "status": "sent"})
    def test_shared_email_alerts_stay_separate_and_auto_workflow(self, send_email):
        t = _tag()
        a, b = f"protecteda{t}", f"protectedb{t}"
        ids = {}
        for n in (a, b):
            self._demo(n)
            r = self._register(n, "shared@example.com")
            self.assertEqual(r.status_code, 201)
            ids[n] = r.get_json()["protected_profile_id"]
        self.assertNotEqual(ids[a], ids[b])

        # Normal account -> REAL, no alert, no email
        r = self._social_signup(f"gardenlover{_tag()}", bio="I grow tomatoes and write about compost.")
        body = r.get_json()
        self.assertEqual(r.status_code, 201)
        self.assertFalse(body["alert_triggered"], body["immediate_analysis"].get("classification"))
        send_email.assert_not_called()

        results = {}
        for target in (a, b):
            before = send_email.call_count
            r = self._social_signup(f"{target}_official")
            body = r.get_json()
            self.assertEqual(r.status_code, 201)
            self.assertIn(body["immediate_analysis"]["classification"], {"SUSPICIOUS", "FAKE"})
            self.assertTrue(body["alert_triggered"])
            self.assertEqual(send_email.call_count, before + 1)
            kwargs = send_email.call_args.kwargs
            self.assertEqual(kwargs["recipient"], "shared@example.com")
            self.assertEqual(kwargs["protected_username"], target)
            alert = query_db("SELECT protected_profile_id, email_status FROM alerts WHERE id=?", (body["alert_id"],), one=True)
            self.assertEqual(alert["protected_profile_id"], ids[target])
            self.assertEqual(alert["email_status"], "sent")
            results[target] = body["alert_id"]
        self.assertNotEqual(results[a], results[b])

        # Second impersonator of the same protected profile -> separate alert + email
        before = send_email.call_count
        r = self._social_signup(f"{a}_real")
        self.assertTrue(r.get_json()["alert_triggered"])
        self.assertEqual(send_email.call_count, before + 1)

        # Same impersonator detected again -> duplicate, no new alert, no email
        demo = query_db("SELECT * FROM demo_profiles WHERE username=?", (f"{a}_official",), one=True)
        alerts_before = query_db("SELECT COUNT(*) n FROM alerts", one=True)["n"]
        before = send_email.call_count
        _, created, _, delivery = monitor_routes.process_new_demo_profile(demo)
        self.assertFalse(created)
        self.assertEqual(delivery["status"], "duplicate")
        self.assertEqual(send_email.call_count, before)
        self.assertEqual(query_db("SELECT COUNT(*) n FROM alerts", one=True)["n"], alerts_before)


class LegacySchemaMigrationTests(unittest.TestCase):
    """init_db must drop a legacy UNIQUE(email) while keeping UNIQUE(username) and existing IDs."""

    def test_legacy_unique_email_constraints_removed(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
        conn = sqlite3.connect(tmp)
        conn.executescript("""
            CREATE TABLE demo_profiles (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL, bio TEXT, avatar_url TEXT, followers_count INTEGER DEFAULT 0);
            CREATE TABLE protected_profiles (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, bio TEXT, avatar_url TEXT, follower_count INTEGER DEFAULT 0, is_monitoring_active INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE registered_profiles (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, original_profile_id INTEGER NOT NULL, registered_at DATETIME DEFAULT CURRENT_TIMESTAMP);
            INSERT INTO protected_profiles (id, username, display_name, email) VALUES (42, 'keepme', 'Keep', 'k@example.com');
        """)
        conn.commit()
        conn.close()
        with patch.object(database, "DATABASE_PATH", tmp):
            init_db()
            init_db()  # idempotent
            c = sqlite3.connect(tmp)
            for table in ("protected_profiles", "registered_profiles"):
                uniques = []
                for idx in c.execute(f"PRAGMA index_list({table})"):
                    if idx[2]:
                        uniques.append([r[2] for r in c.execute(f'PRAGMA index_info("{idx[1]}")')])
                self.assertIn(["username"], uniques, table)
                self.assertNotIn(["email"], uniques, table)
            self.assertEqual(c.execute("SELECT id FROM protected_profiles WHERE username='keepme'").fetchone()[0], 42)
            c.execute("INSERT INTO protected_profiles (username, display_name, email) VALUES ('other', 'O', 'k@example.com')")
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("INSERT INTO protected_profiles (username, display_name, email) VALUES ('keepme', 'K', 'z@example.com')")
            c.close()
        os.unlink(tmp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
