# Finance
A website that simulates a stock investment web app with real prices
## Features
* Registration
    * Password requirements
* Login
    * Password change
* Quoting stocks
* Purchasing stocks
* Selling stocks
* Tracking your balance
    * Adding cash
* Transactions history
## Usage
Create virtual environment
```
python3 -m venv env
```

Activate it
```
source env/bin/activate
```

Install requirements
```
pip install -r requirements.txt
```

Set [IEX](https://iexcloud.io/) API key
```
export API_KEY=value
```

Run server
```
flask run
```