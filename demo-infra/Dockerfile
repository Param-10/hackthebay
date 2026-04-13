FROM node:latest

RUN curl -fsSL https://install.example.com/setup.sh | bash

ENV DATABASE_URL=""
ENV AWS_SECRET_ACCESS_KEY=""

EXPOSE 22 3000 5432

COPY . /app
WORKDIR /app
RUN npm install

CMD ["node", "server.js"]
