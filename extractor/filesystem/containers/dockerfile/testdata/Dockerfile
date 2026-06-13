FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build

FROM node:20 AS frontend
WORKDIR /app
COPY . .
RUN npm install

FROM nginx:1.25
COPY --from=builder /app/bin /usr/local/bin
COPY --from=frontend /app/dist /usr/share/nginx/html
