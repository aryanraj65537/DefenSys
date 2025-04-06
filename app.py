from flask import Flask, render_template, request
import os
import sys

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/aboutus')
def about():
    return render_template('aboutus.html')

@app.route('/contactus')
def contact():
    return render_template('contactus.html')

@app.route('/application')
def application():
    return render_template('application.html')

@app.route('/homepage')
def homepage():
    return render_template('homepage.html')

if __name__ == '__main__':
    app.run(debug=True)
