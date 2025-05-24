import axios from 'axios';

// Динамическое определение API URL на основе текущего хоста
const getApiUrl = () => {
  // Если есть переменная окружения, используем её
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  
  // Иначе определяем динамически на основе текущего хоста
  const protocol = window.location.protocol;
  const hostname = window.location.hostname;
  
  // Если localhost, используем localhost:8000
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return `${protocol}//localhost:8000`;
  }
  
  // Для других хостов используем тот же хост с портом 8000
  return `${protocol}//${hostname}:8000`;
};

const API_URL = getApiUrl();

console.log('API URL:', API_URL); // Для отладки

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Interceptor для добавления токена в запросы
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Interceptor для обработки ответов
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Обработка ошибки 401 (Unauthorized)
    if (error.response && error.response.status === 401) {
      // Удаляем токен и перенаправляем на страницу логина
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// API методы
const apiService = {
  // Установка токена авторизации
  setAuthToken: (token) => {
    if (token) {
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    } else {
      delete api.defaults.headers.common['Authorization'];
    }
  },
  
  // Аутентификация
  login: async (username, password) => {
    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);
    
    return api.post('/token', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
  },
  
  // Обертки для HTTP методов
  get: (url, params) => api.get(url, { params }),
  post: (url, data) => api.post(url, data),
  put: (url, data) => api.put(url, data),
  delete: (url) => api.delete(url),
};

export default apiService;
