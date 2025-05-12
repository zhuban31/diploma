import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Container, Typography, TextField, Button, Box, Paper, 
  FormControl, InputLabel, Select, MenuItem, Divider,
  FormControlLabel, Checkbox, Grid, Accordion, AccordionSummary,
  AccordionDetails, Alert, AlertTitle, CircularProgress
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
  const [useSudo, setUseSudo] = useState(false);
  const [allCriteria, setAllCriteria] = useState([]);
  const [allCategories, setAllCategories] = useState([]);
  const [filteredCategories, setFilteredCategories] = useState([]);
  const [filteredCriteria, setFilteredCriteria] = useState([]);
  const [selectedCriteria, setSelectedCriteria] = useState({});
  const [expandedCategories, setExpandedCategories] = useState({});
  const [loading, setLoading] = useState(false);
  const [fetchingData, setFetchingData] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  const navigate = useNavigate();

  // Загрузка критериев и категорий
  useEffect(() => {
    const fetchData = async () => {
      try {
        setFetchingData(true);
        setError('');
        
        // Загрузка категорий
        const categoriesResponse = await api.get('/criteria_categories/');
        setAllCategories(categoriesResponse.data);
        
        // Загрузка критериев
        const criteriaResponse = await api.get('/criteria/');
        setAllCriteria(criteriaResponse.data);
        
        console.log(`Загружено ${categoriesResponse.data.length} категорий и ${criteriaResponse.data.length} критериев`);
      } catch (error) {
        console.error('Error fetching criteria:', error);
        setError('Failed to load criteria. Please try again later.');
      } finally {
        setFetchingData(false);
      }
    };
    
    fetchData();
  }, []);

  // Фильтрация критериев при изменении типа соединения или при загрузке данных
  useEffect(() => {
    if (allCategories.length > 0 && allCriteria.length > 0) {
      let cats = [];
      let crits = [];
      
      // Определение допустимых категорий для типа соединения
      if (connectionType === 'ssh') {
        // Linux категории (1-12)
        cats = allCategories.filter(cat => cat.id < 13);
        crits = allCriteria.filter(crit => crit.category_id < 13);
        console.log(`Отфильтровано ${cats.length} Linux-категорий и ${crits.length} Linux-критериев`);
      } else if (connectionType === 'winrm') {
        // Windows категории (13+)
        cats = allCategories.filter(cat => cat.id >= 13);
        crits = allCriteria.filter(crit => crit.category_id >= 13);
        console.log(`Отфильтровано ${cats.length} Windows-категорий и ${crits.length} Windows-критериев`);
      }
      
      // Обновление отфильтрованных категорий и критериев
      setFilteredCategories(cats);
      setFilteredCriteria(crits);
      
      // Инициализация выбранных критериев
      const newSelectedCriteria = {};
      crits.forEach(criterion => {
        newSelectedCriteria[criterion.id] = true;
      });
      setSelectedCriteria(newSelectedCriteria);
      
      // Инициализация развернутых категорий
      const newExpandedCategories = {};
      cats.forEach(category => {
        newExpandedCategories[category.id] = false;
      });
      setExpandedCategories(newExpandedCategories);
    }
  }, [connectionType, allCategories, allCriteria]);

  // Обработчик изменения типа соединения
  const handleConnectionTypeChange = (event) => {
    const newType = event.target.value;
    console.log(`Тип соединения изменен: ${connectionType} -> ${newType}`);
    setConnectionType(newType);
    
    // Сброс полей аутентификации
    setUsePassword(true);
    setSshKey('');
    setUseSudo(false);
  };

  // Обработчик запуска сканирования
  const handleScan = async () => {
    setError('');
    setSuccess('');
    
    if (!serverIP) {
      setError('Введите IP-адрес сервера');
      return;
    }
    
    if (!username) {
      setError('Введите имя пользователя');
      return;
    }
    
    if (connectionType === "ssh") {
      if (usePassword && !password) {
        setError('Введите пароль');
        return;
      }
      
      if (!usePassword && !sshKey) {
        setError('Введите путь к SSH-ключу');
        return;
      }
    } else if (connectionType === "winrm") {
      if (!password) {
        setError('Введите пароль');
        return;
      }
    }
    
    // Получаем выбранные критерии
    const selectedCriteriaIds = Object.entries(selectedCriteria)
      .filter(([_, isSelected]) => isSelected)
      .map(([id, _]) => parseInt(id));
    
    if (selectedCriteriaIds.length === 0) {
      setError('Выберите хотя бы один критерий');
      return;
    }
    
    setLoading(true);
    
    try {
      console.log(`Отправка запроса на сканирование ${connectionType}-сервера ${serverIP}`);
      console.log(`Выбрано ${selectedCriteriaIds.length} критериев`);
      
      const response = await api.post('/scan/', {
        server_ip: serverIP,
        username: username,
        password: usePassword || connectionType === "winrm" ? password : null,
        ssh_key: !usePassword && connectionType === "ssh" ? sshKey : null,
        connection_type: connectionType,
        criteria_ids: selectedCriteriaIds,
        use_sudo: connectionType === "ssh" ? useSudo : false
      });
      
      setSuccess('Сканирование успешно завершено!');
      
      // Перенаправляем на страницу результатов
      setTimeout(() => {
        navigate(`/scan-results/${response.data.scan_id}`);
      }, 1500);
      
    } catch (error) {
      console.error('Ошибка сканирования:', error);
      setError(`Сканирование не удалось: ${error.response?.data?.message || 'Неизвестная ошибка'}`);
    } finally {
      setLoading(false);
    }
  };

  // Обработчики выбора критериев
  const handleToggleCategory = (categoryId) => {
    const categoryCriteria = filteredCriteria.filter(c => c.category_id === categoryId);
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
    filteredCriteria.forEach(criterion => {
      newSelectedCriteria[criterion.id] = true;
    });
    setSelectedCriteria(newSelectedCriteria);
  };

  // Снятие выбора со всех критериев
  const deselectAllCriteria = () => {
    const newSelectedCriteria = {};
    filteredCriteria.forEach(criterion => {
      newSelectedCriteria[criterion.id] = false;
    });
    setSelectedCriteria(newSelectedCriteria);
  };

  // Подсчет выбранных критериев
  const countSelectedCriteria = () => {
    const selectedCount = Object.entries(selectedCriteria)
      .filter(([id, isSelected]) => isSelected && filteredCriteria.some(c => c.id === parseInt(id)))
      .length;
    
    return { 
      selected: selectedCount, 
      total: filteredCriteria.length 
    };
  };

  const criteriaCount = countSelectedCriteria();

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
                  onChange={handleConnectionTypeChange}
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
              
              {connectionType === "ssh" ? (
                <>
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
                </>
              ) : (
                <>
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
                  
                  <Alert severity="info" sx={{ mb: 2 }}>
                    <AlertTitle>Требования для сканирования Windows</AlertTitle>
                    <ul>
                      <li>WinRM должен быть включен на целевом сервере</li>
                      <li>Используйте учетную запись администратора</li>
                      <li>Убедитесь, что брандмауэр разрешает WinRM (TCP порты 5985 для HTTP, 5986 для HTTPS)</li>
                    </ul>
                  </Alert>
                </>
              )}
              
              <Button
                variant="contained"
                color="primary"
                fullWidth
                onClick={handleScan}
                disabled={loading || fetchingData}
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
                Security Criteria {connectionType === "winrm" ? "(Windows)" : "(Linux)"}
              </Typography>
              <Typography variant="body2">
                Selected: {criteriaCount.selected} / {criteriaCount.total}
              </Typography>
            </Box>
            
            <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
              <Button 
                variant="outlined" 
                size="small"
                onClick={selectAllCriteria}
                disabled={loading || fetchingData}
              >
                Select All
              </Button>
              <Button 
                variant="outlined" 
                size="small"
                onClick={deselectAllCriteria}
                disabled={loading || fetchingData}
              >
                Deselect All
              </Button>
            </Box>
            
            <Divider sx={{ mb: 2 }} />
            
            <Box sx={{ maxHeight: 400, overflow: 'auto', pr: 1 }}>
              {fetchingData ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                  <CircularProgress />
                </Box>
              ) : filteredCategories.length === 0 ? (
                <Alert severity="info">
                  No criteria available for the selected connection type.
                </Alert>
              ) : (
                filteredCategories.map((category) => {
                  const categoryCriteria = filteredCriteria.filter(c => c.category_id === category.id);
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
                })
              )}
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Container>
  );
};

export default ServerScan;