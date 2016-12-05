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


class WrongCredentialsException(SecurityException):
    def __str__(self):
        return "Wrong Login Credentials"


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


class InvalidUserException(SecurityException):
    def __str__(self):
        return "The user is not logged in or doesnt exist"


class UserAlreadyLoggedInException(SecurityException):
    def __str__(self):
        return "User is Already Logged In"

class MessageTooLongException(SecurityException):
    def __str__(self):
        return "Message is Too Long"

class InvalidMessageTypeException(SecurityException):
    def __str__(self):
        return "Incorrect message type is received"
