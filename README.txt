I. Installation:-
    1. create a folder
    2. Create a virtual environment using virtualenv . (May need to install virtualenv)
    3. copy the files into the folder
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

    Installation is Done!!

II. List of authenticated users:
    In the db we will be providing. The users are
    1. username=secure password=secret
    2. username=secure1 password=secret

    New users can be added by running
        db <username> <password>
    Above command doesnt allow duplicate usernames


III. Running

    Client
        client <client_config> or python cli.py <client_config> (if not installed)

        This will start an interactive session asking for username and password

    Server
        server <server_config> or python server.py <server_config> (if not installed)

        If server running pops up then the server is running
