import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import authenticate

class LoginTests(unittest.TestCase):
    def test_correct_agent_chen(self):
        result = authenticate('agent.chen', 'RedAlert#99')
        self.assertEqual(result['user']['email'], 'mchen@clearancenet.gov')
        self.assertNotIn('password', result['user'])
    def test_correct_director_hayes(self):
        self.assertEqual(authenticate('director.hayes', 'Sector7!Top')['user']['name'], 'Director James Hayes')
    def test_wrong_password(self):
        self.assertFalse(authenticate('agent.chen', 'wrong-password')['ok'])
    def test_unknown_user(self):
        self.assertFalse(authenticate('nobody', 'wrong-password')['ok'])
    def test_empty_credentials(self):
        self.assertFalse(authenticate('', '')['ok'])
    def test_malformed_quote(self):
        self.assertFalse(authenticate("'", 'x')['ok'])
    def test_screenshot_tautology_bypass(self):
        result = authenticate("' OR '1'='1", 'wrong-password')
        self.assertTrue(result['ok'])
        self.assertIn("username = '' OR '1'='1'", result['sql'])
    def test_numeric_tautology_bypass(self):
        self.assertTrue(authenticate("' OR 1=1 -- ", 'wrong-password')['ok'])

if __name__ == '__main__':
    unittest.main()
