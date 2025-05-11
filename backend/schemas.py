from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime

# User schemas
class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    is_active: bool

    class Config:
        orm_mode = True

# Authentication schemas
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# Criteria schemas
class CriterionBase(BaseModel):
    name: str
    description: Optional[str] = None
    check_command: str
    expected_output: Optional[str] = None
    remediation: Optional[str] = None
    severity: str
    automated: bool = False

class CriterionCreate(CriterionBase):
    category_id: int

class Criterion(CriterionBase):
    id: int
    category_id: int

    class Config:
        orm_mode = True

# Category schemas
class CriterionCategoryBase(BaseModel):
    name: str
    description: Optional[str] = None

class CriterionCategoryCreate(CriterionCategoryBase):
    pass

class CriterionCategory(CriterionCategoryBase):
    id: int
    criteria: List[Criterion] = []

    class Config:
        orm_mode = True

# Scan schemas
class ScanBase(BaseModel):
    server_ip: str
    connection_type: str

class ScanCreate(ScanBase):
    user_id: int

class Scan(ScanBase):
    id: int
    user_id: int
    timestamp: datetime
    status: str

    class Config:
        orm_mode = True

# Scan result schemas
class ScanResultBase(BaseModel):
    criterion_id: int
    status: str
    details: Optional[str] = None
    remediation: Optional[str] = None

class ScanResultCreate(ScanResultBase):
    scan_id: int

class ScanResult(ScanResultBase):
    id: int
    scan_id: int

    class Config:
        orm_mode = True

# Extended schemas for API
class ScanRequest(BaseModel):
    server_ip: str
    username: str
    password: Optional[str] = None
    ssh_key: Optional[str] = None
    connection_type: str = "ssh"
    criteria_ids: List[int]
    use_sudo: bool = False  # Новое поле для использования sudo

class ScanResponse(BaseModel):
    scan_id: int
    results: List[dict]
    status: str
    message: str

class ScanDetail(BaseModel):
    scan: Scan
    results: List[ScanResult]

    class Config:
        orm_mode = True