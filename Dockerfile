FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application files
COPY server.js ./
COPY public ./public

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Create and use a non-root user
RUN addgroup -g 1001 -S nodejs && adduser -S -G nodejs -u 1001 nodejs
RUN chown -R nodejs:nodejs /app
USER nodejs
# Run the application
CMD ["node", "server.js"]
