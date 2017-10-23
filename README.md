# apisrv
Test assignment from company ***

`Tested with Python 3.5`


Clone this repository:

```bash
$ git clone git@github.com:andrewnsk/apisrv.git
```

activate virtualenv (optional)

install requirements:

```bash
$ cd ./apisrv
$ pip install -r requirements.txt
```

then create empty SQLite database by command:

```bash
$ python create_db.py
```

then run api service:
```bash
$ python apisrv.py
```


Dev server work's on http://0.0.0.0:5000/

## Tests
In the other console, cd to tests folder:
```bash
$ cd path_to_apisrv/tests/
$ python test_api.py
```