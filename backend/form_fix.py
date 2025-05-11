from fastapi import FastAPI, Depends, HTTPException, status, Form, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from typing import List, Optional
import models, schemas, crud, auth
from database import SessionLocal, engine, Base
import paramiko
import json
import csv
from io import StringIO
import asyncio
import logging
import os
from datetime import datetime, timedelta

app = FastAPI(title="Server Security Audit", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

@app.get("/test-login", response_class=HTMLResponse)
async def get_test_login():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Login</title>
        <style>
            body { font-family: Arial; max-width: 500px; margin: 50px auto; padding: 20px; }
            .form-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; }
            input { width: 100%; padding: 8px; }
            button { padding: 10px 15px; background-color: blue; color: white; border: none; }
        </style>
    </head>
    <body>
        <h2>Direct Login Test</h2>
        <form action="/token" method="post" enctype="application/x-www-form-urlencoded">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" value="admin">
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" value="admin123">
            </div>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """
