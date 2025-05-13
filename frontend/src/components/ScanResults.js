import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Container, Typography, Box, Paper, Button, Chip, Divider,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  TablePagination, TextField, Select, MenuItem, FormControl, InputLabel,
  Alert, CircularProgress, Accordion, AccordionSummary, AccordionDetails
} from '@mui/material';
import {
  ExpandMore, GetApp, ArrowBack, CheckCircle, ErrorOutline, Warning
} from '@mui/icons-material';
import api from '../services/api';

const ScanResults = () => {
  const { scanId } = useParams();
  const navigate = useNavigate();
  
  const [scanData, setScanData] = useState(null);
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Filters and pagination
  const [filteredResults, setFilteredResults] = useState([]);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  
  // Statistics
  const [stats, setStats] = useState({
    total: 0,
    pass: 0,
    fail: 0,
    warning: 0,
    error: 0,
    high: 0,
    medium: 0,
    low: 0
  });

  useEffect(() => {
    const fetchScanData = async () => {
      try {
        setLoading(true);
        setError('');
        
        const response = await api.get(`/scans/${scanId}`);
        setScanData(response.data.scan);
        
        // Get criteria for each result
        const criteriaMap = {};
        try {
          const criteriaResponse = await api.get('/criteria/');
          criteriaResponse.data.forEach(criterion => {
            criteriaMap[criterion.id] = criterion;
          });
        } catch (err) {
          console.error('Error fetching criteria:', err);
        }
        
        // Enhance results with criteria data
        const enhancedResults = response.data.results.map(result => {
          const criterion = criteriaMap[result.criterion_id] || {
            name: `Criterion #${result.criterion_id}`,
            severity: 'Unknown',
            description: 'Unknown criterion'
          };
          
          return {
            ...result,
            criterion
          };
        });
        
        setResults(enhancedResults);
        
        // Calculate statistics
        const stats = {
          total: enhancedResults.length,
          pass: enhancedResults.filter(r => r.status === 'Pass').length,
          fail: enhancedResults.filter(r => r.status === 'Fail').length,
          warning: enhancedResults.filter(r => r.status === 'Warning').length,
          error: enhancedResults.filter(r => r.status === 'Error').length,
          high: enhancedResults.filter(r => r.criterion?.severity === 'High').length,
          medium: enhancedResults.filter(r => r.criterion?.severity === 'Medium').length,
          low: enhancedResults.filter(r => r.criterion?.severity === 'Low').length
        };
        
        setStats(stats);
        
      } catch (err) {
        console.error('Error fetching scan results:', err);
        setError('Failed to load scan results. Please try again later.');
      } finally {
        setLoading(false);
      }
    };
    
    fetchScanData();
  }, [scanId]);

  // Apply filters
  useEffect(() => {
    if (results.length > 0) {
      let filtered = [...results];
      
      // Search term filter
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        filtered = filtered.filter(result => 
          result.criterion?.name.toLowerCase().includes(term) ||
          result.details?.toLowerCase().includes(term) ||
          result.remediation?.toLowerCase().includes(term)
        );
      }
      
      // Status filter
      if (statusFilter !== 'all') {
        filtered = filtered.filter(result => result.status === statusFilter);
      }
      
      // Severity filter
      if (severityFilter !== 'all') {
        filtered = filtered.filter(result => result.criterion?.severity === severityFilter);
      }
      
      setFilteredResults(filtered);
      // Reset to first page when filters change
      setPage(0);
    }
  }, [results, searchTerm, statusFilter, severityFilter]);

  // Handle pagination
  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  // СОВЕРШЕННО НОВЫЙ ПОДХОД К ЭКСПОРТУ JSON/CSV
  const handleExport = async () => {
  try {
    // Экспорт JSON - используем существующие данные
    const exportData = results.map(result => ({
      id: result.id,
      criterion: result.criterion.name,
      status: result.status,
      severity: result.criterion.severity,
      details: result.details ? result.details.replace(/\n/g, ' ') : '',
      remediation: result.remediation ? result.remediation.replace(/\n/g, ' ') : ''
    }));
    
    const content = JSON.stringify(exportData, null, 2);
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan_${scanId}_results.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error('Error exporting JSON:', err);
    setError('Failed to export results as JSON');
  }
};

  // Status indicator component
  const StatusIndicator = ({ status }) => {
    switch (status) {
      case 'Pass':
        return <Chip icon={<CheckCircle />} label="Pass" color="success" size="small" />;
      case 'Fail':
        return <Chip icon={<ErrorOutline />} label="Fail" color="error" size="small" />;
      case 'Warning':
        return <Chip icon={<Warning />} label="Warning" color="warning" size="small" />;
      case 'Error':
        return <Chip icon={<ErrorOutline />} label="Error" color="secondary" size="small" />;
      default:
        return <Chip label={status} size="small" />;
    }
  };

  // Severity indicator component
  const SeverityIndicator = ({ severity }) => {
    switch (severity) {
      case 'High':
        return <Chip label="High" color="error" size="small" variant="outlined" />;
      case 'Medium':
        return <Chip label="Medium" color="warning" size="small" variant="outlined" />;
      case 'Low':
        return <Chip label="Low" color="info" size="small" variant="outlined" />;
      default:
        return <Chip label={severity || 'Unknown'} size="small" variant="outlined" />;
    }
  };

  if (loading) {
    return (
      <Container sx={{ mt: 4, display: 'flex', justifyContent: 'center', alignItems: 'center', flexDirection: 'column' }}>
        <CircularProgress />
        <Typography sx={{ mt: 2 }}>Loading scan results...</Typography>
      </Container>
    );
  }

  if (error) {
    return (
      <Container sx={{ mt: 4 }}>
        <Alert severity="error">{error}</Alert>
        <Button 
          variant="outlined" 
          startIcon={<ArrowBack />} 
          onClick={() => navigate('/history')}
          sx={{ mt: 2 }}
        >
          Back to Scan History
        </Button>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <Button 
          variant="outlined" 
          startIcon={<ArrowBack />} 
          onClick={() => navigate('/history')}
          sx={{ mr: 2 }}
        >
          Back
        </Button>
        <Typography variant="h4">Scan Results</Typography>
      </Box>
      
      {scanData && (
        <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>Scan Information</Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
            <Box>
              <Typography variant="subtitle2" color="text.secondary">Server IP</Typography>
              <Typography>{scanData.server_ip}</Typography>
            </Box>
            <Box>
              <Typography variant="subtitle2" color="text.secondary">Connection Type</Typography>
              <Typography>{scanData.connection_type.toUpperCase()}</Typography>
            </Box>
            <Box>
              <Typography variant="subtitle2" color="text.secondary">Date</Typography>
              <Typography>{new Date(scanData.timestamp).toLocaleString()}</Typography>
            </Box>
            <Box>
              <Typography variant="subtitle2" color="text.secondary">Status</Typography>
              <Chip 
                label={scanData.status.charAt(0).toUpperCase() + scanData.status.slice(1)} 
                color={scanData.status === 'completed' ? 'success' : (scanData.status === 'failed' ? 'error' : 'info')}
                size="small"
              />
            </Box>
          </Box>
          
          <Divider sx={{ my: 2 }} />
          
          <Typography variant="subtitle1" gutterBottom>Summary</Typography>
          
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
            <Paper elevation={1} sx={{ p: 1, minWidth: 100, textAlign: 'center' }}>
              <Typography variant="h6">{stats.total}</Typography>
              <Typography variant="body2">Total</Typography>
            </Paper>
            <Paper elevation={1} sx={{ p: 1, minWidth: 100, textAlign: 'center', bgcolor: 'success.light', color: 'white' }}>
              <Typography variant="h6">{stats.pass}</Typography>
              <Typography variant="body2">Pass</Typography>
            </Paper>
            <Paper elevation={1} sx={{ p: 1, minWidth: 100, textAlign: 'center', bgcolor: 'error.light', color: 'white' }}>
              <Typography variant="h6">{stats.fail}</Typography>
              <Typography variant="body2">Fail</Typography>
            </Paper>
            <Paper elevation={1} sx={{ p: 1, minWidth: 100, textAlign: 'center', bgcolor: 'warning.light', color: 'white' }}>
              <Typography variant="h6">{stats.warning}</Typography>
              <Typography variant="body2">Warning</Typography>
            </Paper>
            
            <Divider orientation="vertical" flexItem />
            
            <Paper elevation={1} sx={{ p: 1, minWidth: 100, textAlign: 'center', bgcolor: 'error.main', color: 'white' }}>
              <Typography variant="h6">{stats.high}</Typography>
              <Typography variant="body2">High Risk</Typography>
            </Paper>
            <Paper elevation={1} sx={{ p: 1, minWidth: 100, textAlign: 'center', bgcolor: 'warning.main', color: 'white' }}>
              <Typography variant="h6">{stats.medium}</Typography>
              <Typography variant="body2">Medium Risk</Typography>
            </Paper>
            <Paper elevation={1} sx={{ p: 1, minWidth: 100, textAlign: 'center', bgcolor: 'info.main', color: 'white' }}>
              <Typography variant="h6">{stats.low}</Typography>
              <Typography variant="body2">Low Risk</Typography>
            </Paper>
          </Box>
          
          <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 2 }}>
            <Button 
              variant="outlined" 
              startIcon={<GetApp />} 
              onClick={() => handleExport('json')}
              sx={{ mr: 1 }}
            >
              Export JSON
            </Button>
          </Box>
        </Paper>
      )}
      
      <Paper elevation={3} sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>Detailed Results</Typography>
        
        <Box sx={{ mb: 3, display: 'flex', flexWrap: 'wrap', gap: 2 }}>
          <TextField
            label="Search"
            variant="outlined"
            size="small"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            sx={{ minWidth: 200 }}
          />
          
          <FormControl sx={{ minWidth: 150 }} size="small">
            <InputLabel>Status</InputLabel>
            <Select
              value={statusFilter}
              label="Status"
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <MenuItem value="all">All Statuses</MenuItem>
              <MenuItem value="Pass">Pass</MenuItem>
              <MenuItem value="Fail">Fail</MenuItem>
              <MenuItem value="Warning">Warning</MenuItem>
              <MenuItem value="Error">Error</MenuItem>
            </Select>
          </FormControl>
          
          <FormControl sx={{ minWidth: 150 }} size="small">
            <InputLabel>Severity</InputLabel>
            <Select
              value={severityFilter}
              label="Severity"
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <MenuItem value="all">All Severities</MenuItem>
              <MenuItem value="High">High</MenuItem>
              <MenuItem value="Medium">Medium</MenuItem>
              <MenuItem value="Low">Low</MenuItem>
            </Select>
          </FormControl>
        </Box>
        
        {filteredResults.length > 0 ? (
          <>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Criterion</TableCell>
                    <TableCell align="center">Status</TableCell>
                    <TableCell align="center">Severity</TableCell>
                    <TableCell>Details</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredResults
                    .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                    .map((result) => (
                      <TableRow key={result.id}>
                        <TableCell>{result.criterion?.name}</TableCell>
                        <TableCell align="center">
                          <StatusIndicator status={result.status} />
                        </TableCell>
                        <TableCell align="center">
                          <SeverityIndicator severity={result.criterion?.severity} />
                        </TableCell>
                        <TableCell>
                          <Accordion>
                            <AccordionSummary expandIcon={<ExpandMore />}>
                              <Typography variant="body2">
                                {result.status === 'Pass' ? 'Passed check' : 'View details'}
                              </Typography>
                            </AccordionSummary>
                            <AccordionDetails>
                              <Typography variant="subtitle2">Details:</Typography>
                              <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', mb: 1 }}>
                                {result.details || 'No details available'}
                              </Typography>
                              
                              {result.status !== 'Pass' && result.remediation && (
                                <>
                                  <Typography variant="subtitle2" sx={{ mt: 1 }}>Remediation:</Typography>
                                  <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                                    {result.remediation}
                                  </Typography>
                                </>
                              )}
                            </AccordionDetails>
                          </Accordion>
                        </TableCell>
                      </TableRow>
                    ))}
                </TableBody>
              </Table>
            </TableContainer>
            
            <TablePagination
              rowsPerPageOptions={[10, 25, 50, 100]}
              component="div"
              count={filteredResults.length}
              rowsPerPage={rowsPerPage}
              page={page}
              onPageChange={handleChangePage}
              onRowsPerPageChange={handleChangeRowsPerPage}
            />
          </>
        ) : (
          <Alert severity="info">
            No results found matching your filters. Try adjusting your search criteria.
          </Alert>
        )}
      </Paper>
    </Container>
  );
};

export default ScanResults;