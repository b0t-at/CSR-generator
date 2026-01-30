FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --omit=dev

# Copy application files
COPY server.js ./
COPY healthcheck.js ./
COPY public ./public

# Create and use a non-root user for security
RUN addgroup -g 1001 -S nodejs && adduser -S -G nodejs -u 1001 nodejs && chown -R nodejs:nodejs /app
USER nodejs

# Expose port
EXPOSE 3000

# Health check using dedicated script for better maintainability
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node healthcheck.js

# Run the application
CMD ["node", "server.js"]
