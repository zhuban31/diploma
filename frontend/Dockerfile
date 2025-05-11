FROM node:18-alpine as build

WORKDIR /app

# Копирование package.json и установка зависимостей
COPY package.json package-lock.json* ./
RUN npm install

# Копирование исходного кода
COPY . .

# Сборка для продакшена
RUN npm run build

# Установка и конфигурация serve для раздачи статики
RUN npm install -g serve

# Экспозиция порта
EXPOSE 3000

# Запуск сервера
CMD ["serve", "-s", "build", "-l", "3000"]
