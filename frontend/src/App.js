import React from 'react';
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
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? children : <Navigate to="/login" />;
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
      </Routes>
    </>
  );
}

export default App;
