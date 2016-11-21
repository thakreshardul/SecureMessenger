class SecurityException(Exception):
    def __init__(self):
        pass


class InvalidSolutionException(SecurityException):
    def __init__(self):
        pass

    def __str__(self):
        return "Got Wrong Solution for Puzzle"


class InvalidTimeStampException(SecurityException):
    def __init__(self):
        pass

    def __str__(self):
        return "Packet has Invalid Timestamp"


class InvalidUsernameException(SecurityException):
    def __str__(self):
        return "Given Username is invalid"


class PasswordMismatchException(SecurityException):
    def __init__(self):
        pass

    def __str__(self):
        return "Password for Username is Incorrect"


class InvalidCertificateException(SecurityException):
    def __init__(self):
        pass

    def __str__(self):
        return "Puzzle Certificate is Invalid"


class InvalidSignatureException(SecurityException):
    def __init__(self):
        pass

    def __str__(self):
        return "Signature of Packet is Invalid"


class InvalidTagException(SecurityException):
    def __init__(self):
        pass

    def __str__(self):
        return "Tag of Packet is Invalid"
