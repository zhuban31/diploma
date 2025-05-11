from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text, DateTime, Float, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    
    scans = relationship("Scan", back_populates="user")

class CriterionCategory(Base):
    __tablename__ = "criterion_categories"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    
    criteria = relationship("Criterion", back_populates="category")

class Criterion(Base):
    __tablename__ = "criteria"
    
    id = Column(Integer, primary_key=True, index=True)
    category_id = Column(Integer, ForeignKey("criterion_categories.id"))
    name = Column(String, index=True)
    description = Column(Text)
    check_command = Column(Text)
    expected_output = Column(Text)
    remediation = Column(Text)
    severity = Column(Enum("Low", "Medium", "High", name="severity_enum"), index=True)
    automated = Column(Boolean, default=False)
    
    category = relationship("CriterionCategory", back_populates="criteria")
    scan_results = relationship("ScanResult", back_populates="criterion")

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    server_ip = Column(String, index=True)
    connection_type = Column(Enum("ssh", "winrm", name="connection_type_enum"))
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(Enum("running", "completed", "failed", name="scan_status_enum"), default="running")
    
    user = relationship("User", back_populates="scans")
    results = relationship("ScanResult", back_populates="scan")

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    criterion_id = Column(Integer, ForeignKey("criteria.id"))
    status = Column(Enum("Pass", "Fail", "Warning", "Error", name="result_status_enum"))
    details = Column(Text)
    remediation = Column(Text)
    
    scan = relationship("Scan", back_populates="results")
    criterion = relationship("Criterion", back_populates="scan_results")
