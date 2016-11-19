# All Named Tuples Here
from collections import namedtuple

Certificate = namedtuple('Certificate',
                         ['timestamp', 'difficulty', 'nonce_s', 'sign'])

ServerUser = namedtuple('ServerUser',
                        ['username', 'pass_hash', 'salt', 'public_key', 'key',
                         'addr'])

ClientUser = namedtuple('ClientUser',
                        ['username', 'public_key', 'dh_public_key', 'key',
                         'addr'])
