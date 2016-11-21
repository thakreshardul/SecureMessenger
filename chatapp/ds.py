# All Named Tuples Here
from collections import namedtuple

Certificate = namedtuple('Certificate',
                         ['timestamp', 'difficulty', 'nonce_s', 'sign'])

Solution = namedtuple('Solution', ['nonce_c', 'x'])