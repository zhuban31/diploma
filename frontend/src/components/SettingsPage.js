import React, { useState } from 'react';
import { Container, Typography, Paper, Box, Button, TextField, Alert, Snackbar, Grid, Divider } from '@mui/material';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';

const SettingsPage = () => {
  const { user } = useAuth();
  
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [passwordSuccess, setPasswordSuccess] = useState(false);
  
  const handlePasswordChange = async (e) => {
    e.preventDefault();
    setPasswordError('');
    
    if (!currentPassword) {
      setPasswordError('Please enter your current password');
      return;
    }
    
    if (!newPassword) {
      setPasswordError('Please enter a new password');
      return;
    }
    
    if (newPassword.length < 8) {
      setPasswordError('New password must be at least 8 characters long');
      return;
    }
    
    if (newPassword !== confirmPassword) {
      setPasswordError('New passwords do not match');
      return;
    }
    
    try {
      // This is a placeholder for API call. In reality, you would call your backend API
      // await api.put('/users/me/password', {
      //   current_password: currentPassword,
      //   new_password: newPassword
      // });
      
      // For now, just simulate success
      setPasswordSuccess(true);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      
      // Hide success message after 5 seconds
      setTimeout(() => {
        setPasswordSuccess(false);
      }, 5000);
      
    } catch (error) {
      console.error('Failed to change password:', error);
      setPasswordError('Failed to change password. Please check your current password and try again.');
    }
  };
  
  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>
        Settings
      </Typography>
      
      <Grid container spacing={3}>
        {/* Account Settings */}
        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Account Settings
            </Typography>
            <Divider sx={{ mb: 3 }} />
            
            <Box sx={{ mb: 3 }}>
              <Typography variant="subtitle2" color="text.secondary">
                Username
              </Typography>
              <Typography>{user?.username}</Typography>
            </Box>
            
            <Box sx={{ mb: 3 }}>
              <Typography variant="subtitle2" color="text.secondary">
                Email
              </Typography>
              <Typography>{user?.email}</Typography>
            </Box>
            
            <Typography variant="h6" gutterBottom sx={{ mt: 4 }}>
              Change Password
            </Typography>
            <Divider sx={{ mb: 3 }} />
            
            {passwordError && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {passwordError}
              </Alert>
            )}
            
            <form onSubmit={handlePasswordChange}>
              <TextField
                margin="normal"
                required
                fullWidth
                label="Current Password"
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
              />
              <TextField
                margin="normal"
                required
                fullWidth
                label="New Password"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                helperText="Password must be at least 8 characters long"
              />
              <TextField
                margin="normal"
                required
                fullWidth
                label="Confirm New Password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
              <Button
                type="submit"
                variant="contained"
                color="primary"
                sx={{ mt: 3 }}
              >
                Change Password
              </Button>
            </form>
          </Paper>
        </Grid>
        
        {/* Scan Settings */}
        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Scan Settings
            </Typography>
            <Divider sx={{ mb: 3 }} />
            
            <Typography variant="body2" color="text.secondary">
              These settings are applied to all new scans.
            </Typography>
            
            <Box sx={{ mt: 3 }}>
              <Typography variant="subtitle2" gutterBottom>
                Default Connection Settings
              </Typography>
              
              <TextField
                margin="normal"
                fullWidth
                label="Default SSH Username"
                value="root"
                disabled
                helperText="This feature will be available in a future update"
              />
              
              <TextField
                margin="normal"
                fullWidth
                label="Default SSH Port"
                value="22"
                disabled
                helperText="This feature will be available in a future update"
              />
            </Box>
            
            <Box sx={{ mt: 3 }}>
              <Typography variant="subtitle2" gutterBottom>
                Scan Behavior
              </Typography>
              
              <TextField
                margin="normal"
                fullWidth
                label="Connection Timeout (seconds)"
                value="30"
                disabled
                helperText="This feature will be available in a future update"
              />
              
              <TextField
                margin="normal"
                fullWidth
                label="Command Timeout (seconds)"
                value="60"
                disabled
                helperText="This feature will be available in a future update"
              />
            </Box>
          </Paper>
        </Grid>
      </Grid>
      
      <Snackbar
        open={passwordSuccess}
        autoHideDuration={5000}
        onClose={() => setPasswordSuccess(false)}
      >
        <Alert severity="success" sx={{ width: '100%' }}>
          Password changed successfully!
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default SettingsPage;
