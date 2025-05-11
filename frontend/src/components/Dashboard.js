import React, { useState, useEffect } from 'react';
import { Container, Grid, Paper, Typography, Box, Button } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { Security, History, Settings } from '@mui/icons-material';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

const Dashboard = () => {
  const [stats, setStats] = useState({
    totalScans: 0,
    passedCriteria: 0,
    failedCriteria: 0,
    warningCriteria: 0
  });
  const [recentScans, setRecentScans] = useState([]);
  const { user } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Получение историии сканирований
        const scansResponse = await api.get('/scans/');
        setRecentScans(scansResponse.data.slice(0, 5)); // Получаем только 5 последних
        
        // Рассчитываем статистику
        if (scansResponse.data.length > 0) {
          let passed = 0;
          let failed = 0;
          let warning = 0;
          
          for (const scan of scansResponse.data.slice(0, 5)) {
            // Для каждого сканирования получаем результаты
            const resultsResponse = await api.get(`/scans/${scan.id}`);
            
            passed += resultsResponse.data.results.filter(r => r.status === 'Pass').length;
            failed += resultsResponse.data.results.filter(r => r.status === 'Fail').length;
            warning += resultsResponse.data.results.filter(r => r.status === 'Warning').length;
          }
          
          setStats({
            totalScans: scansResponse.data.length,
            passedCriteria: passed,
            failedCriteria: failed,
            warningCriteria: warning
          });
        }
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
      }
    };
    
    fetchData();
  }, []);

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>
      <Typography variant="subtitle1" gutterBottom>
        Welcome back, {user?.username}
      </Typography>
      
      <Grid container spacing={3} sx={{ mt: 2 }}>
        {/* Quick Actions */}
        <Grid item xs={12} md={4}>
          <Paper elevation={3} sx={{ p: 3, display: 'flex', flexDirection: 'column', height: 240 }}>
            <Typography variant="h6" gutterBottom>
              Quick Actions
            </Typography>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 2 }}>
              <Button 
                variant="contained" 
                color="primary" 
                startIcon={<Security />}
                onClick={() => navigate('/scan')}
              >
                New Server Scan
              </Button>
              <Button 
                variant="outlined" 
                startIcon={<History />}
                onClick={() => navigate('/history')}
              >
                View Scan History
              </Button>
              <Button 
                variant="outlined" 
                startIcon={<Settings />}
                onClick={() => navigate('/settings')}
              >
                Configure Settings
              </Button>
            </Box>
          </Paper>
        </Grid>
        
        {/* Statistics */}
        <Grid item xs={12} md={8}>
          <Paper elevation={3} sx={{ p: 3, display: 'flex', flexDirection: 'column', height: 240 }}>
            <Typography variant="h6" gutterBottom>
              Statistics
            </Typography>
            <Grid container spacing={2} sx={{ mt: 1 }}>
              <Grid item xs={6} md={3}>
                <Paper elevation={1} sx={{ p: 2, textAlign: 'center', bgcolor: 'primary.light', color: 'white' }}>
                  <Typography variant="h4">{stats.totalScans}</Typography>
                  <Typography variant="body2">Total Scans</Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} md={3}>
                <Paper elevation={1} sx={{ p: 2, textAlign: 'center', bgcolor: 'success.light', color: 'white' }}>
                  <Typography variant="h4">{stats.passedCriteria}</Typography>
                  <Typography variant="body2">Passed</Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} md={3}>
                <Paper elevation={1} sx={{ p: 2, textAlign: 'center', bgcolor: 'error.light', color: 'white' }}>
                  <Typography variant="h4">{stats.failedCriteria}</Typography>
                  <Typography variant="body2">Failed</Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} md={3}>
                <Paper elevation={1} sx={{ p: 2, textAlign: 'center', bgcolor: 'warning.light', color: 'white' }}>
                  <Typography variant="h4">{stats.warningCriteria}</Typography>
                  <Typography variant="body2">Warnings</Typography>
                </Paper>
              </Grid>
            </Grid>
          </Paper>
        </Grid>
        
        {/* Recent Scans */}
        <Grid item xs={12}>
          <Paper elevation={3} sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Recent Scans
            </Typography>
            {recentScans.length > 0 ? (
              <Box>
                {recentScans.map((scan) => (
                  <Box 
                    key={scan.id} 
                    sx={{ 
                      p: 2, 
                      mb: 1, 
                      border: '1px solid', 
                      borderColor: 'divider',
                      borderRadius: 1,
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center'
                    }}
                  >
                    <Box>
                      <Typography variant="subtitle1">
                        Server: {scan.server_ip}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Status: {scan.status} | Date: {new Date(scan.timestamp).toLocaleString()}
                      </Typography>
                    </Box>
                    <Button 
                      variant="outlined" 
                      size="small"
                      onClick={() => navigate(`/scan-results/${scan.id}`)}
                    >
                      View Details
                    </Button>
                  </Box>
                ))}
              </Box>
            ) : (
              <Typography variant="body1" sx={{ mt: 2 }}>
                No recent scans found. Start by scanning a server.
              </Typography>
            )}
          </Paper>
        </Grid>
      </Grid>
    </Container>
  );
};

export default Dashboard;
