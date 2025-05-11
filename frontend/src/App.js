import React, { useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';

// Components
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import ServerScan from './components/ServerScan';
import ScanResults from './components/ScanResults';
import ScanHistory from './components/ScanHistory';
import SettingsPage from './components/SettingsPage';
import Navbar from './components/Navbar';
import { AuthProvider, useAuth } from './context/AuthContext';

// Создаем тему
const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#2196f3',
    },
    secondary: {
      main: '#f50057',
    },
    background: {
      default: '#f5f5f5',
    },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
  },
});

// Защищенный маршрут
const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();
  
  // Если идет проверка токена - показываем загрузку
  if (loading) {
    return <div>Loading...</div>;
  }
  
  // Если не авторизован - перенаправляем на логин
  if (!isAuthenticated) {
    return <Navigate to="/login" />;
  }
  
  return children;
};

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <AuthProvider>
        <Router>
          <AppContent />
        </Router>
      </AuthProvider>
    </ThemeProvider>
  );
}

function AppContent() {
  const { isAuthenticated } = useAuth();
  
  // Проверка токена при загрузке
  useEffect(() => {
    const token = localStorage.getItem('token');
    console.log('Token in localStorage:', token);
    
    // Здесь можно добавить дополнительную логику проверки
  }, []);

  return (
    <>
      {isAuthenticated && <Navbar />}
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        } />
        <Route path="/scan" element={
          <ProtectedRoute>
            <ServerScan />
          </ProtectedRoute>
        } />
        <Route path="/scan-results/:scanId" element={
          <ProtectedRoute>
            <ScanResults />
          </ProtectedRoute>
        } />
        <Route path="/history" element={
          <ProtectedRoute>
            <ScanHistory />
          </ProtectedRoute>
        } />
        <Route path="/settings" element={
          <ProtectedRoute>
            <SettingsPage />
          </ProtectedRoute>
        } />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </>
  );
}

export default App;
