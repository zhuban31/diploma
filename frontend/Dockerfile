FROM node:18-alpine

WORKDIR /app

# Копируем только package.json сначала
COPY package.json ./

# Устанавливаем зависимости
RUN npm install

# Затем копируем остальные файлы
COPY . .

# Запускаем в режиме разработки
EXPOSE 3000
CMD ["npm", "start"]