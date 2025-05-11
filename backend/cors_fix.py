from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import List, Optional
import logging

# Настройка CORS
def setup_cors(app):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )
    
    # Добавляем маршрут для проверки CORS
    @app.options("/{rest_of_path:path}")
    async def preflight_handler(rest_of_path: str):
        response = JSONResponse(
            status_code=200,
            content={"message": "OK"}
        )
        return response

# Для добавления в main.py
