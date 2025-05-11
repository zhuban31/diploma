#!/bin/bash
# Скрипт для запуска приложения Server Security Audit

# Установка цветного вывода
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Server Security Audit - Запуск ===${NC}"

# Запуск контейнеров
echo -e "${BLUE}Запуск контейнеров с Docker Compose...${NC}"
docker-compose up -d

# Проверка успешного запуска
if [ $? -ne 0 ]; then
    echo -e "${RED}Ошибка при запуске контейнеров!${NC}"
    exit 1
fi

echo -e "${GREEN}Контейнеры успешно запущены!${NC}"

# Ожидание запуска базы данных
echo -e "${BLUE}Ожидание запуска базы данных...${NC}"
sleep 10

# Импорт критериев безопасности
echo -e "${BLUE}Импорт критериев безопасности из paste.txt...${NC}"
docker-compose exec backend python import_criteria.py

if [ $? -ne 0 ]; then
    echo -e "${RED}Ошибка при импорте критериев безопасности!${NC}"
else
    echo -e "${GREEN}Критерии безопасности успешно импортированы!${NC}"
fi

# Создание первого пользователя
echo -e "${BLUE}Создание первого пользователя...${NC}"
docker-compose exec backend python create_first_user.py --username admin --password admin123 --email admin@example.com

if [ $? -ne 0 ]; then
    echo -e "${RED}Ошибка при создании пользователя!${NC}"
else
    echo -e "${GREEN}Пользователь успешно создан!${NC}"
fi

echo -e "\n${GREEN}=== Server Security Audit успешно запущен! ===${NC}"
echo -e "${YELLOW}Доступ к приложению:${NC}"
echo -e "  - Веб-интерфейс: ${BLUE}http://localhost:3000${NC}"
echo -e "  - API: ${BLUE}http://localhost:8000${NC}"
echo -e "  - Документация API: ${BLUE}http://localhost:8000/docs${NC}"
echo -e "\n${YELLOW}Учетные данные по умолчанию:${NC}"
echo -e "  - Пользователь: ${BLUE}admin${NC}"
echo -e "  - Пароль: ${BLUE}admin123${NC}"
echo -e "\n${RED}ВАЖНО: Для продакшн-окружения смените пароль администратора!${NC}"
