import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Container, Typography, TextField, Button, Box, Paper, 
  FormControl, InputLabel, Select, MenuItem, Divider,
  FormControlLabel, Checkbox, Grid, Accordion, AccordionSummary,
  AccordionDetails, Alert, CircularProgress
} from '@mui/material';
import { ExpandMore, Security, NetworkCheck } from '@mui/icons-material';
import api from '../services/api';

const ServerScan = () => {
  const [serverIP, setServerIP] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [sshKey, setSshKey] = useState('');
  const [connectionType, setConnectionType] = useState('ssh');
  const [usePassword, setUsePassword] = useState(true);
  const [useSudo, setUseSudo] = useState(false); // Добавлен флаг для использования sudo
  const [criteria, setCriteria] = useState([]);
  const [criteriaCategories, setCriteriaCategories] = useState([]);
  const [selectedCriteria, setSelectedCriteria] = useState({});
  const [expandedCategories, setExpandedCategories] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  const navigate = useNavigate();

  // Загрузка критериев и категорий
  useEffect(() => {
    const fetchData = async () => {
      try {
        const categoriesResponse = await api.get('/criteria_categories/');
        setCriteriaCategories(categoriesResponse.data);
        
        const criteriaResponse = await api.get('/criteria/');
        setCriteria(criteriaResponse.data);
        
        // Инициализация выбранных критериев и развернутых категорий
        const initialSelectedCriteria = {};
        const initialExpandedCategories = {};
        
        criteriaResponse.data.forEach(criterion => {
          initialSelectedCriteria[criterion.id] = true;
        });
        
        categoriesResponse.data.forEach(category => {
          initialExpandedCategories[category.id] = false;
        });
        
        setSelectedCriteria(initialSelectedCriteria);
        setExpandedCategories(initialExpandedCategories);
        
      } catch (error) {
        console.error('Error fetching criteria:', error);
        setError('Failed to load criteria. Please try again later.');
      }
    };
    
    fetchData();
  }, []);

  // Обработчик запуска сканирования
  const handleScan = async () => {
    setError('');
    setSuccess('');
    
    if (!serverIP) {
      setError('Please enter server IP address');
      return;
    }
    
    if (!username) {
      setError('Please enter username');
      return;
    }
    
    if (usePassword && !password) {
      setError('Please enter password');
      return;
    }
    
    if (!usePassword && !sshKey) {
      setError('Please enter SSH key path');
      return;
    }
    
    // Получаем выбранные критерии
    const selectedCriteriaIds = Object.entries(selectedCriteria)
      .filter(([_, isSelected]) => isSelected)
      .map(([id, _]) => parseInt(id));
    
    if (selectedCriteriaIds.length === 0) {
      setError('Please select at least one criterion');
      return;
    }
    
    setLoading(true);
    
    try {
      const response = await api.post('/scan/', {
        server_ip: serverIP,
        username: username,
        password: usePassword ? password : null,
        ssh_key: !usePassword ? sshKey : null,
        connection_type: connectionType,
        criteria_ids: selectedCriteriaIds,
        use_sudo: useSudo // Передаем флаг использования sudo
      });
      
      setSuccess('Scan completed successfully!');
      
      // Перенаправляем на страницу результатов
      setTimeout(() => {
        navigate(`/scan-results/${response.data.scan_id}`);
      }, 1500);
      
    } catch (error) {
      console.error('Scan error:', error);
      setError(`Scan failed: ${error.response?.data?.message || 'Unknown error'}`);
    } finally {
      setLoading(false);
    }
  };

  // Обработчики выбора критериев
  const handleToggleCategory = (categoryId) => {
    const categoryCriteria = criteria.filter(c => c.category_id === categoryId);
    const newSelectedCriteria = { ...selectedCriteria };
    
    // Проверяем, все ли критерии в категории выбраны
    const allSelected = categoryCriteria.every(c => selectedCriteria[c.id]);
    
    // Если все выбраны, снимаем выбор со всех, иначе выбираем все
    categoryCriteria.forEach(criterion => {
      newSelectedCriteria[criterion.id] = !allSelected;
    });
    
    setSelectedCriteria(newSelectedCriteria);
  };
  
  const handleToggleCriterion = (criterionId) => {
    setSelectedCriteria({
      ...selectedCriteria,
      [criterionId]: !selectedCriteria[criterionId]
    });
  };

  const handleExpandCategory = (categoryId) => {
    setExpandedCategories({
      ...expandedCategories,
      [categoryId]: !expandedCategories[categoryId]
    });
  };

  // Выбор всех критериев
  const selectAllCriteria = () => {
    const newSelectedCriteria = {};
    criteria.forEach(criterion => {
      newSelectedCriteria[criterion.id] = true;
    });
    setSelectedCriteria(newSelectedCriteria);
  };

  // Снятие выбора со всех критериев
  const deselectAllCriteria = () => {
    const newSelectedCriteria = {};
    criteria.forEach(criterion => {
      newSelectedCriteria[criterion.id] = false;
    });
    setSelectedCriteria(newSelectedCriteria);
  };

  // Подсчет выбранных критериев
  const countSelectedCriteria = () => {
    return Object.values(selectedCriteria).filter(value => value).length;
  };

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>
        Server Scan
      </Typography>
      
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      
      {success && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {success}
        </Alert>
      )}
      
      <Grid container spacing={3}>
        {/* Server Connection Settings */}
        <Grid item xs={12} md={5}>
          <Paper elevation={3} sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Server Connection
            </Typography>
            <Box sx={{ mt: 2 }}>
              <TextField
                label="Server IP"
                variant="outlined"
                fullWidth
                value={serverIP}
                onChange={(e) => setServerIP(e.target.value)}
                sx={{ mb: 2 }}
                placeholder="e.g. 192.168.1.10"
                disabled={loading}
              />
              
              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Connection Type</InputLabel>
                <Select
                  value={connectionType}
                  label="Connection Type"
                  onChange={(e) => setConnectionType(e.target.value)}
                  disabled={loading}
                >
                  <MenuItem value="ssh">SSH (Linux/Unix)</MenuItem>
                  <MenuItem value="winrm">WinRM (Windows)</MenuItem>
                </Select>
              </FormControl>
              
              <TextField
                label="Username"
                variant="outlined"
                fullWidth
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                sx={{ mb: 2 }}
                disabled={loading}
              />
              
              <FormControlLabel
                control={
                  <Checkbox
                    checked={usePassword}
                    onChange={(e) => setUsePassword(e.target.checked)}
                    disabled={loading}
                  />
                }
                label="Use Password"
                sx={{ mb: 1 }}
              />
              
              {usePassword ? (
                <TextField
                  label="Password"
                  variant="outlined"
                  fullWidth
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  sx={{ mb: 2 }}
                  disabled={loading}
                />
              ) : (
                <TextField
                  label="SSH Key Path"
                  variant="outlined"
                  fullWidth
                  value={sshKey}
                  onChange={(e) => setSshKey(e.target.value)}
                  sx={{ mb: 2 }}
                  placeholder="e.g. /path/to/private_key"
                  disabled={loading}
                />
              )}
              
              {/* Добавлен чекбокс для использования sudo */}
              <FormControlLabel
                control={
                  <Checkbox
                    checked={useSudo}
                    onChange={(e) => setUseSudo(e.target.checked)}
                    disabled={loading}
                  />
                }
                label="Use sudo for commands (requires sudo privileges)"
                sx={{ mb: 2 }}
              />
              
              <Button
                variant="contained"
                color="primary"
                fullWidth
                onClick={handleScan}
                disabled={loading}
                startIcon={loading ? <CircularProgress size={20} /> : <NetworkCheck />}
                sx={{ mt: 2 }}
              >
                {loading ? 'Scanning...' : 'Start Scan'}
              </Button>
            </Box>
          </Paper>
        </Grid>
        
        {/* Criteria Selection */}
        <Grid item xs={12} md={7}>
          <Paper elevation={3} sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">
                Security Criteria
              </Typography>
              <Typography variant="body2">
                Selected: {countSelectedCriteria()} / {criteria.length}
              </Typography>
            </Box>
            
            <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
              <Button 
                variant="outlined" 
                size="small"
                onClick={selectAllCriteria}
                disabled={loading}
              >
                Select All
              </Button>
              <Button 
                variant="outlined" 
                size="small"
                onClick={deselectAllCriteria}
                disabled={loading}
              >
                Deselect All
              </Button>
            </Box>
            
            <Divider sx={{ mb: 2 }} />
            
            <Box sx={{ maxHeight: 400, overflow: 'auto', pr: 1 }}>
              {criteriaCategories.map((category) => {
                const categoryCriteria = criteria.filter(c => c.category_id === category.id);
                const selectedCount = categoryCriteria.filter(c => selectedCriteria[c.id]).length;
                
                return (
                  <Accordion 
                    key={category.id} 
                    expanded={expandedCategories[category.id]}
                    onChange={() => handleExpandCategory(category.id)}
                    disabled={loading}
                  >
                    <AccordionSummary expandIcon={<ExpandMore />}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', width: '100%', alignItems: 'center' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                          <Checkbox 
                            checked={selectedCount === categoryCriteria.length && categoryCriteria.length > 0}
                            indeterminate={selectedCount > 0 && selectedCount < categoryCriteria.length}
                            onChange={() => handleToggleCategory(category.id)}
                            onClick={(e) => e.stopPropagation()}
                            disabled={loading}
                          />
                          <Typography>{category.name}</Typography>
                        </Box>
                        <Typography variant="body2" color="text.secondary">
                          {selectedCount}/{categoryCriteria.length}
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      {categoryCriteria.map((criterion) => (
                        <Box 
                          key={criterion.id} 
                          sx={{ 
                            mb: 1, 
                            p: 1, 
                            display: 'flex', 
                            alignItems: 'flex-start',
                            borderBottom: '1px solid',
                            borderColor: 'divider'
                          }}
                        >
                          <Checkbox 
                            checked={!!selectedCriteria[criterion.id]}
                            onChange={() => handleToggleCriterion(criterion.id)}
                            disabled={loading}
                          />
                          <Box>
                            <Typography variant="body2">{criterion.name}</Typography>
                            <Typography variant="caption" color="text.secondary">
                              Severity: {criterion.severity} | {criterion.automated ? 'Automated' : 'Manual'}
                            </Typography>
                          </Box>
                        </Box>
                      ))}
                    </AccordionDetails>
                  </Accordion>
                );
              })}
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Container>
  );
};

export default ServerScan;