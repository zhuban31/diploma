from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Расширенная настройка CORS
def configure_cors(app):
    app.add_middleware(
        CORSMiddleware,
        # Явно добавляем оба варианта доступа
        allow_origins=[
            "http://localhost:3000",
            "http://25.15.212.99:3000",
            "*"  # Разрешаем все источники
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )
