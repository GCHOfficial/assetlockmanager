# Stage 1: Build the React application
FROM node:20 AS builder

# Set working directory
WORKDIR /app/frontend

# Copy package.json and pnpm-lock.yaml first for dependency caching
COPY package.json pnpm-lock.yaml ./

# Install pnpm
RUN npm install -g pnpm

# Install dependencies using pnpm
RUN pnpm install --frozen-lockfile

# Copy the rest of the frontend source code
COPY . .

# Build the application
# Ensure build outputs to the default 'dist' directory
RUN pnpm build

# Stage 2: Serve the application with Nginx
FROM nginx:stable-alpine

# Copy the built application from the builder stage to Nginx web root
COPY --from=builder /app/frontend/dist /var/www/html

# Copy the custom Nginx configuration (Corrected path relative to build context)
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"] 