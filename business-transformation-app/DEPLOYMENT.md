<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Deployment Guide

## Quick Start

### On Windows (PowerShell or Command Prompt)
```bash
cd business-transformation-app
npm install
npm run dev
```

### On Linux/Mac/WSL
```bash
cd business-transformation-app
chmod +x install-and-run.sh
./install-and-run.sh
```

Or manually:
```bash
cd business-transformation-app
npm install
npm run dev
```

## Access the App

Once the server starts, open your browser to:
- **Local**: http://localhost:3000
- **Network**: http://[your-ip]:3000

## Production Deployment

### Build for Production
```bash
npm run build
npm start
```

### Deploy to Vercel (Recommended)
```bash
npm install -g vercel
vercel login
vercel
```

Follow the prompts to deploy.

### Deploy to Netlify
1. Build the app: `npm run build`
2. Upload the `.next` folder to Netlify
3. Set build command: `npm run build`
4. Set publish directory: `.next`

### Deploy with Docker
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npm", "start"]
```

Build and run:
```bash
docker build -t business-transform .
docker run -p 3000:3000 business-transform
```

## Environment Variables

Create a `.env.local` file if needed:
```env
# Add any environment variables here
NEXT_PUBLIC_APP_URL=http://localhost:3000
```

## Troubleshooting

### Port Already in Use
```bash
# Windows
netstat -ano | findstr :3000
taskkill /PID <PID> /F

# Linux/Mac
lsof -ti:3000 | xargs kill -9
```

### Build Errors
1. Delete `node_modules` and `.next` folders
2. Run `npm install` again
3. Run `npm run build`

### TypeScript Errors
```bash
npm run lint
```

## Performance Optimization

The app is optimized for production with:
- Code splitting
- Image optimization
- Minification
- Tree shaking
- Browser caching

## Browser Support

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Mobile browsers (iOS Safari, Chrome Mobile)

## PWA Installation

The app can be installed as a Progressive Web App:
1. Open the app in browser
2. Click the install icon in the address bar
3. Follow prompts to install

## Data Backup

Export your data regularly:
1. Go to Settings
2. Click "Export Data"
3. Save the JSON file

To restore:
1. Go to Settings
2. Click "Import Data"
3. Select your backup file

## Support

For issues, check:
1. Node.js version: `node -v` (should be >= 18.0.0)
2. npm version: `npm -v` (should be >= 9.0.0)
3. Browser console for errors
4. Network tab for failed requests

---

**Ready to Transform Your Business!** 🚀




