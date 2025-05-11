import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container, Typography, Paper, Box, Button, Chip,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  TablePagination, TextField, Alert, CircularProgress
} from '@mui/material';
import { Visibility, ArrowBack } from '@mui/icons-material';
import api from '../services/api';

const ScanHistory = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [filteredScans, setFilteredScans] = useState([]);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  
  const navigate = useNavigate();

  useEffect(() => {
    const fetchScans = async () => {
      try {
        setLoading(true);
        setError('');
        
        const response = await api.get('/scans/');
        setScans(response.data);
      } catch (err) {
        console.error('Error fetching scan history:', err);
        setError('Failed to load scan history. Please try again later.');
      } finally {
        setLoading(false);
      }
    };
    
    fetchScans();
  }, []);

  // Filter scans when search term changes
  useEffect(() => {
    if (scans.length > 0) {
      let filtered = [...scans];
      
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        filtered = filtered.filter(scan => 
          scan.server_ip.toLowerCase().includes(term) ||
          scan.status.toLowerCase().includes(term) ||
          new Date(scan.timestamp).toLocaleString().toLowerCase().includes(term)
        );
      }
      
      setFilteredScans(filtered);
      setPage(0);
    }
  }, [scans, searchTerm]);

  // Handle pagination
  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  // Status indicator component
  const StatusChip = ({ status }) => {
    switch (status) {
      case 'completed':
        return <Chip label="Completed" color="success" size="small" />;
      case 'running':
        return <Chip label="Running" color="primary" size="small" />;
      case 'failed':
        return <Chip label="Failed" color="error" size="small" />;
      default:
        return <Chip label={status} size="small" />;
    }
  };

  if (loading) {
    return (
      <Container sx={{ mt: 4, display: 'flex', justifyContent: 'center', alignItems: 'center', flexDirection: 'column' }}>
        <CircularProgress />
        <Typography sx={{ mt: 2 }}>Loading scan history...</Typography>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <Button 
          variant="outlined" 
          startIcon={<ArrowBack />} 
          onClick={() => navigate('/')}
          sx={{ mr: 2 }}
        >
          Back to Dashboard
        </Button>
        <Typography variant="h4">Scan History</Typography>
      </Box>
      
      <Paper elevation={3} sx={{ p: 3 }}>
        <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6">Previous Scans</Typography>
          <TextField
            label="Search"
            variant="outlined"
            size="small"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            sx={{ width: 300 }}
          />
        </Box>
        
        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}
        
        {filteredScans.length > 0 ? (
          <>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Server IP</TableCell>
                    <TableCell>Date</TableCell>
                    <TableCell>Connection Type</TableCell>
                    <TableCell align="center">Status</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredScans
                    .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                    .map((scan) => (
                      <TableRow key={scan.id}>
                        <TableCell>{scan.server_ip}</TableCell>
                        <TableCell>{new Date(scan.timestamp).toLocaleString()}</TableCell>
                        <TableCell>{scan.connection_type.toUpperCase()}</TableCell>
                        <TableCell align="center">
                          <StatusChip status={scan.status} />
                        </TableCell>
                        <TableCell align="right">
                          <Button
                            variant="outlined"
                            size="small"
                            startIcon={<Visibility />}
                            onClick={() => navigate(`/scan-results/${scan.id}`)}
                            disabled={scan.status === 'running'}
                          >
                            View Results
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                </TableBody>
              </Table>
            </TableContainer>
            
            <TablePagination
              rowsPerPageOptions={[10, 25, 50, 100]}
              component="div"
              count={filteredScans.length}
              rowsPerPage={rowsPerPage}
              page={page}
              onPageChange={handleChangePage}
              onRowsPerPageChange={handleChangeRowsPerPage}
            />
          </>
        ) : (
          <Alert severity="info">
            No scan history found. Start by scanning a server.
          </Alert>
        )}
      </Paper>
    </Container>
  );
};

export default ScanHistory;
