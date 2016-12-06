from setuptools import setup, find_packages

setup(
    name='chatapp',
    version='0.1',
    install_requires=["cryptography"],
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'db = chatapp.db:add_user',
            'client = chatapp.cli:run',
            'server = chatapp.server:run'
        ]}
)