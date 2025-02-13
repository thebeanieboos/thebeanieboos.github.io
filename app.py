# to update website run: set FLASK_APP=app.py
# to actually start the website run: flask run
import subprocess
import sys
import pycurl
subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
import datetime
import requests
import applemusicpy
import jwt
import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
app = Flask(__name__)

@app.route('/', methods = ['GET', 'POST'])
def main():
    if request.method == 'POST':
        songs = song_search(request.form.get('song'))
        return(render_template('main.html', songs=songs))
    else:
        return render_template('main.html')
    
#info to generate token 
time_now = datetime.datetime.now()
time_expired = datetime.datetime.now() + datetime.timedelta(hours = 1)
alg = "ES256"
secret = "41364ffed544483daa8bac13b6afae9b"
private_key_path = "AuthKey_L9G55JT6AU (1).p8.txt"
key_id = 'L9G55JT6AU'
team_id = '2YUQ6YV6DF'
client_id = 'com.ethan1'

with open(private_key_path, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print(public_pem.decode('utf-8'))

headers = {
    'kid': key_id,
}

payload = {
    'iss': team_id,
    'iat': time_now,
    'exp': time_expired,
    'aud': 'https://appleid.apple.com',
    'sub': client_id,
}

client_secret = jwt.encode(payload, private_key, algorithm='ES256', headers=headers)
print(client_secret)

data = {
    client_id: 'com.ethan1',
    client_secret: 'eyJhbGciOiJFUzI1NiIsImtpZCI6Ikw5RzU1SlQ2QVUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiIyWVVRNllWNkRGIiwiaWF0IjoxNzM5NDQyOTUyLCJleHAiOjE3Mzk0NDY1NTIsImF1ZCI6Imh0dHBzOi8vYXBwbGVpZC5hcHBsZS5jb20iLCJzdWIiOiJjb20uZXRoYW4xIn0.BsCls_lCUTr3hr4lRkE1h1SGOdlL8JqlE_8IJNeoc5hin0V4x3wRTNkX_Ud5956OPEMiwElWEiBUh_e6NDkLGw',
    code: 'CODE',
    grant_type: 'authorization_code',
    redirect_uri: 'themusicrater.com',
}

response = requests.post('http://POST', data=data)
response = requests.post('https://appleid.apple.com/auth/token', data=data)
'''
response = requests.post(url, headers=headers, json=data)
am = applemusicpy.client.AppleMusic(secret_key, key_id, team_id)
def song_search(song):
    raw_results = am.search(song, types=['songs'], limit=5)
    refined_results = []
    for i in range(len(raw_results["results"]["songs"]["data"])):
        refined_results.append(raw_results["results"]["songs"]["data"][i]["attributes"]["name"])
    print(refined_results)
    return refined_results
'''

if __name__ == '__main__':
    app.run(debug=True)