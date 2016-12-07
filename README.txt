I. Installation:-
    1. create a folder
    2. Create a virtual environment using virtualenv (May need to install virtualenv)
    3. copy the files extracted into the folder where the bin folder created by virtualenv is present
       Then cd to that folder
    4. source bin/activate
    5. install all cryptography dependencies using apt-get or yum
       Make sure openssl is updated to latest version
    6. Run python setup.py install
    7. If cryptography doesnt install properly please install it manually
    8. Create client_config.json
        Sample:
        {
         "server-ip": "127.0.0.1",
         "server-port": 6000,
         "client-ip": "127.0.0.1",
         "client-port": 5000
        }
    9. Create server_config.json
        Sample:
        {
           "server-ip": "127.0.0.1",
           "server-port": 6000
           "num-threads": 5
        }

    10. You can replace the existing priv.der or pub.der with your own, but should be in DER format
        And named the same. 

    Installation is Done!!

All following commands or scripts should be run from the root folder of the project. 
( The folder which has chatapp and setup.py)
If running the scripts directly then PYTHONPATH should also be set to the root folder of the project. 

II. List of authenticated users:
    In the db we will be providing. The users are
    1. username=secure password=secret
    2. username=secure1 password=secret

    New users can be added by running
        db <username> <password> or python db.py <username> <password> (if not installed)
    Above command doesnt allow Duplicate usernames


III. Running

    Client
        client <client_config> or python cli.py <client_config> (if not installed)

        This will start an interactive session asking for username and password

    Server
        server <server_config> or python server.py <server_config> (if not installed)

        If server running pops up then the server is running
