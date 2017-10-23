"""
Integration tests for the apisrv project
These are "live" executions, that of course
need the apisrv web API to be running.

Try / except is needed for continuing test when an assertion fails,
this happens when random_login give the same LOGIN_NAME ,
that has already been created.
I know, this is bad practice.

But all errors is saved in self.verificationErrors

"""
import requests
import unittest
import json
from random import choice

_APP_JSON_HEADER = 'application/json'

SUCCESS = 200
CREATED = 201
BAD_REQUEST = 400
UNAUTHORIZED = 401
NOT_FOUND = 404
CONFLICT = 409

LOGIN_NAMES = ('Quentin', 'Daniel', 'Tomas', 'Alton', 'Stanford', 'Quentin34', 'Daniel67', 'Tomas1', 'Alton4',
               'Simon', 'Wm', 'Bob', 'Stephan', 'Frank', 'Stevie', 'Simon7', 'Wm55', 'Bob32', 'Stephan12', 'Frank07',
               'Trinidad', 'Gonzalo', 'Moshe', 'Carl', 'Grover', 'Trinidad', 'Gonzalo', 'Moshe', 'Carl', 'Grover',
               'Leo', 'Enoch', 'Barry', 'Hugh', 'Pam', 'Ha', 'Trinidad8', 'Gonzalo9', 'Moshe000', 'Carl54', 'Grover3',
               'Britney', 'Roxane', 'Linette', 'Maryellen', 'Li', 'Britney23', 'Roxane43', 'Linette23', 'Maryellen1',
               'Johna', 'Tasia', 'Cammie', 'Kaitlyn', 'Wendi', 'Johna5', 'Tasia9', 'Cammie7', 'Kaitlyn4', 'Wendi3',
               'Pandora', 'Norma', 'Lucille', 'Pandora65', 'Norma34', 'Lucille25')

DOMAIN_NAMES = ('HOT-WIFI', 'MICROSOFT', 'IT', 'FILESERVER', 'MONKEY', )
PASSWORD_BLANK = ''
PASSWORDS_WITH_LOWERCASE_LETTERS_8_CHARS = ('hekqnsfg', 'amsqlern', )
PASSWORDS_WITH_LOWERCASE_LETTERS_5_CHARS = ('naqmw', 'lamqw', )
PASSWORDS_WITH_LOWERCASE_LETTERS_AND_NUMBERS_8_CHARS = ('h4ks2nqz', 'ldn2nasf', )
PASSWORDS_WITH_LOWERCASE_LETTERS_AND_NUMBERS_AND_SPECIAL_CHAR_8 = ('hw4m2@n1', 'j89m&4ka', )

PASSWORDS_WITH_UPPECASE_LETTERS_8_CHARS = ('HEKQNSFG', 'AMSQLERN', )
PASSWORDS_WITH_UPPECASE_LETTERS_5_CHARS = ('NAQMW', 'LAMQW', )
PASSWORDS_WITH_UPPECASE_LETTERS_AND_NUMBERS_8_CHARS = ('H4KS2NQZ', 'LDN2NASF', )
PASSWORDS_WITH_UPPECASE_LETTERS_AND_NUMBERS_AND_SPECIAL_CHAR_8 = ('HW4M2@N1', 'J89M&4KA', )

PASSWORDS_WITH_MIXED_LETTERS_8_CHARS = ('hekqNSFG', 'AMSqleRN', )
PASSWORDS_WITH_MIXED_LETTERS_5_CHARS = ('NAqmW', 'LAmqw', )
PASSWORDS_WITH_MIXED_LETTERS_AND_NUMBERS_8_CHARS = ('H4KS2nqz', 'ldN2NASF', )
PASSWORDS_WITH_MIXED_LETTERS_AND_NUMBERS_AND_SPECIAL_CHAR_8 = ('Hw4M2@n1', 'J89m&4ka', )


class IntegrationTestsApiFunctionality(unittest.TestCase):

    def __init__(self, *a, **kw):
        super(IntegrationTestsApiFunctionality, self).__init__(*a, **kw)
        self.host = 'localhost'
        self.url = 'http://{}:5000/api/accounts'.format(self.host)
        self.supervisor = {'login': 'root', 'password': 'root'}

    def setUp(self):
        self.verificationErrors = []

    def tearDown(self):
        print(self.verificationErrors)
        # self.assertEqual([], self.verificationErrors)

    def test_login_incorrect_header(self):
        kwargs = {'login': 'root', 'password': 'root', 'headers': 'application/wrong_value'}
        status_code, token = self._get_token_for_user(**kwargs)
        self.assertEqual(status_code, BAD_REQUEST)

    def test_supervisor_login(self):
        kwargs = self.supervisor
        status_code, _token = self._get_token_for_user(**kwargs)
        self.assertEqual(status_code, SUCCESS)

    def test_user_creation_with_lowercase_8_char_password(self):
        """
        By default PasswordPolicy is length >= 8 chars
        """
        random_login = "{}".format(choice(LOGIN_NAMES))
        random_password = "{}".format(choice(PASSWORDS_WITH_LOWERCASE_LETTERS_8_CHARS))
        kwargs = {'login': random_login, 'password': random_password}
        status_code, _json = self._create_account(**kwargs)
        self.assertEqual(status_code, CREATED)
        self.assertIn(random_login, self._get_list_of_users('login'))

    def test_user_creation_with_lowercase_5_char_password(self):
        random_login = "{}".format(choice(LOGIN_NAMES))
        random_password = "{}".format(choice(PASSWORDS_WITH_LOWERCASE_LETTERS_5_CHARS))
        kwargs = {'login': random_login, 'password': random_password}
        status_code, _json = self._create_account(**kwargs)
        try:
            self.assertEqual(status_code, BAD_REQUEST)
        except AssertionError as e:
            self.verificationErrors.append(str(e))

    def test_user_creation_with_lowercase_numbers_8_char_password(self):
        random_login = "{}".format(choice(LOGIN_NAMES))
        random_password = "{}".format(choice(PASSWORDS_WITH_LOWERCASE_LETTERS_AND_NUMBERS_8_CHARS))
        kwargs = {'login': random_login, 'password': random_password}
        status_code, _json = self._create_account(**kwargs)
        try:
            self.assertEqual(status_code, CREATED)
        except AssertionError as e:
            self.verificationErrors.append(str(e))

    def test_user_creation_with_lowercase_numbers_special_8_char_password(self):
        random_login = "{}".format(choice(LOGIN_NAMES))
        random_password = "{}".format(choice(PASSWORDS_WITH_LOWERCASE_LETTERS_AND_NUMBERS_AND_SPECIAL_CHAR_8))
        kwargs = {'login': random_login, 'password': random_password}
        status_code, _json = self._create_account(**kwargs)
        try:
            self.assertEqual(status_code, CREATED)
        except AssertionError as e:
            self.verificationErrors.append(str(e))

    def test_user_creation_with_uppercase_8_char_password(self):
        random_login = "{}".format(choice(LOGIN_NAMES))
        random_password = "{}".format(choice(PASSWORDS_WITH_UPPECASE_LETTERS_8_CHARS))
        kwargs = {'login': random_login, 'password': random_password}
        status_code, _json = self._create_account(**kwargs)
        try:
            self.assertEqual(status_code, CREATED)
        except AssertionError as e:
            self.verificationErrors.append(str(e))

    def test_user_creation_with_uppercase_5_char_password(self):
        random_login = "{}".format(choice(LOGIN_NAMES))
        random_password = "{}".format(choice(PASSWORDS_WITH_UPPECASE_LETTERS_5_CHARS))
        kwargs = {'login': random_login, 'password': random_password}
        status_code, _json = self._create_account(**kwargs)
        try:
            self.assertEqual(status_code, BAD_REQUEST)
        except AssertionError as e:
            self.verificationErrors.append(str(e))

    def test_user_creation_with_uppercase_numbers_8_char_password(self):
        random_login = "{}".format(choice(LOGIN_NAMES))
        random_password = "{}".format(choice(PASSWORDS_WITH_UPPECASE_LETTERS_AND_NUMBERS_8_CHARS))
        kwargs = {'login': random_login, 'password': random_password}
        status_code, _json = self._create_account(**kwargs)
        try:
            self.assertEqual(status_code, CREATED)
        except AssertionError as e:
            self.verificationErrors.append(str(e))

    def test_user_creation_with_uppercase_numbers_special_8_char_password(self):
        random_login = "{}".format(choice(LOGIN_NAMES))
        random_password = "{}".format(choice(PASSWORDS_WITH_UPPECASE_LETTERS_AND_NUMBERS_AND_SPECIAL_CHAR_8))
        kwargs = {'login': random_login, 'password': random_password}
        status_code, _json = self._create_account(**kwargs)
        try:
            self.assertEqual(status_code, CREATED)
        except AssertionError as e:
            self.verificationErrors.append(str(e))

    def test_user_creation_with_not_unique_login(self):
        kwargs = {'login': 'root', 'password': 'tOoRijdns4&'}
        status_code, token = self._create_account(**kwargs)
        self.assertEqual(status_code, CONFLICT)

    def test_user_creation_with_empty_password(self):
        random_login = "{}".format(choice(LOGIN_NAMES))
        empty_password = ""
        kwargs = {'login': random_login, 'password': empty_password}
        status_code, _json = self._create_account(**kwargs)
        self.assertEqual(status_code, BAD_REQUEST)

    def test_user_deletion(self):
        user_id = 2
        status_code, _json = self._delete_account(user_id=user_id)
        self.assertEqual(status_code, SUCCESS)

    def _get_token_for_user(self, login, password, headers=_APP_JSON_HEADER):
        _url = self.url
        _headers = {'content-type': headers}
        _json = {"login": login, "password": password}
        if login:
            r = requests.post(_url + '/login', json=_json, headers=_headers)
            return r.status_code, r.json()

    def _get_accounts(self, headers=_APP_JSON_HEADER):
        _url = self.url
        kwargs = self.supervisor
        _headers = {'content-type': headers,
                    'Authorization': 'Bearer {}'.format(self._get_token_for_user(**kwargs)[1]['jwt'])}
        r = requests.get(_url, headers=_headers)

        return r.status_code, r.json()

    def _get_list_of_users(self, key):
        _, data = self._get_accounts()
        return map(lambda x: x.get(key), data.get('users'))

    def _create_account(self, login, password, headers=_APP_JSON_HEADER):
        _url = self.url
        kwargs = self.supervisor
        _headers = {'content-type': headers,
                    'Authorization': 'Bearer {}'.format(self._get_token_for_user(**kwargs)[1]['jwt'])}
        _json = {"login": login, "password": password}
        if login:
            r = requests.post(_url, json=_json, headers=_headers)
            return r.status_code, r.json()

    def _delete_account(self, user_id, headers=_APP_JSON_HEADER):
        _url = self.url
        kwargs = self.supervisor
        _headers = {'content-type': headers,
                    'Authorization': 'Bearer {}'.format(self._get_token_for_user(**kwargs)[1]['jwt'])}
        if user_id:
            r = requests.delete(_url + '/{}'.format(user_id), headers=_headers)
            return r.status_code, r.json()


if __name__ == '__main__':
    unittest.main(verbosity=2)
