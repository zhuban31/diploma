import React, { createContext, useState, useContext, useEffect } from 'react';
import api from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Проверка токена при загрузке
    const checkToken = async () => {
      if (token) {
        try {
          // Установка токена для API запросов
          api.setAuthToken(token);
          
          // Получение данных пользователя
          const response = await api.get('/users/me/');
          setUser(response.data);
          setIsAuthenticated(true);
        } catch (error) {
          console.error('Auth token validation failed:', error);
          localStorage.removeItem('token');
          setToken(null);
          setIsAuthenticated(false);
        }
      }
      setLoading(false);
    };

    checkToken();
  }, [token]);

  const login = async (username, password) => {
    try {
      const response = await api.login(username, password);
      const { access_token } = response.data;
      
      setToken(access_token);
      localStorage.setItem('token', access_token);
      
      // Установка токена для API запросов
      api.setAuthToken(access_token);
      
      // Получение данных пользователя
      const userResponse = await api.get('/users/me/');
      setUser(userResponse.data);
      setIsAuthenticated(true);
      
      return true;
    } catch (error) {
      console.error('Login failed:', error);
      return false;
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
    setIsAuthenticated(false);
    // Сброс токена в API
    api.setAuthToken(null);
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
