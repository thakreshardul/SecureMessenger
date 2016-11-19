class ChatException(Exception):
    def __init__(self):
        pass


class InvalidSolutionException(ChatException):
    def __init__(self):
        pass


class InvalidTimeStampException(ChatException):
    def __init__(self):
        pass


class PasswordMismatchException(ChatException):
    def __init__(self):
        pass
