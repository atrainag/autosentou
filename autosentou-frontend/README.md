# Autosentou Frontend

Modern, responsive web interface for the Autosentou automated penetration testing platform.

## Features

- **Dashboard**: Overview of all scans with statistics and quick actions
- **Scan Creation**: Configure and launch new penetration tests
- **Job Monitoring**: Real-time progress tracking with phase-by-phase updates
- **Vulnerability Viewer**: Interactive vulnerability cards with detailed information
- **Report Viewer**: View and download reports in PDF, DOCX, and Markdown formats
- **Wordlist Manager**: Upload and manage custom wordlists

## Tech Stack

- **Vue 3** (Composition API)
- **Vue Router** - Client-side routing
- **Pinia** - State management
- **Axios** - HTTP client
- **TailwindCSS** - Utility-first CSS framework
- **HeadlessUI** - Unstyled, accessible components
- **Heroicons** - Beautiful icons
- **Chart.js** - Data visualization
- **date-fns** - Date utilities
- **Vite** - Build tool

## Prerequisites

- Node.js 18+ and npm
- Autosentou backend running on `http://localhost:8000`

## Installation

1. **Install dependencies:**

```bash
npm install
```

2. **Configure environment variables:**

```bash
cp .env.example .env
```

Edit `.env` and set your backend API URL:

```
VITE_API_BASE_URL=http://localhost:8000
```

## Development

Start the development server:

```bash
npm run dev
```

The application will be available at `http://localhost:3000`

## Building for Production

Build the application:

```bash
npm run build
```

Preview the production build:

```bash
npm run preview
```

The built files will be in the `dist` directory.

## Project Structure

```
autosentou-frontend/
├── src/
│   ├── components/          # Reusable Vue components
│   │   ├── common/          # Common UI components
│   │   ├── dashboard/       # Dashboard-specific components
│   │   ├── scan/            # Scan creation components
│   │   ├── jobs/            # Jobs list components
│   │   └── job-detail/      # Job detail components
│   ├── views/               # Page components (routes)
│   │   ├── Dashboard.vue
│   │   ├── ScanCreate.vue
│   │   ├── JobsList.vue
│   │   ├── JobDetail.vue
│   │   ├── ReportViewer.vue
│   │   └── WordlistManager.vue
│   ├── stores/              # Pinia state stores
│   │   ├── jobs.js          # Jobs state management
│   │   ├── wordlists.js     # Wordlists state
│   │   └── app.js           # App-level state
│   ├── services/            # API services
│   │   └── api.js           # Axios configuration & API methods
│   ├── router/              # Vue Router configuration
│   │   └── index.js
│   ├── utils/               # Utility functions
│   │   ├── formatters.js    # Date, size, status formatters
│   │   └── validators.js    # Input validation functions
│   ├── assets/              # Static assets
│   │   └── css/
│   │       └── main.css     # Tailwind directives & custom styles
│   ├── App.vue              # Root component
│   └── main.js              # Application entry point
├── index.html               # HTML entry point
├── vite.config.js           # Vite configuration
├── tailwind.config.js       # TailwindCSS configuration
├── postcss.config.js        # PostCSS configuration
├── package.json             # Project dependencies
└── README.md                # This file
```

## Key Features Explained

### Real-time Job Monitoring

The application uses polling (every 3 seconds) to fetch job updates when a scan is active. This ensures users see real-time progress through the 6 phases:

1. Information Gathering
2. Web Enumeration
3. Vulnerability Analysis
4. SQL Injection Testing
5. Authentication Testing
6. Report Generation

### State Management

Pinia stores manage:
- **Jobs Store**: All job-related data, polling logic, and API calls
- **Wordlists Store**: Wordlist management and upload functionality
- **App Store**: Global app state (sidebar, notifications, backend connection)

### API Communication

All API calls go through `services/api.js`, which provides:
- Axios instance with base configuration
- Request/response interceptors
- Typed API methods for jobs, wordlists, and reports

### Styling

The application uses a cybersecurity-themed dark mode design with:
- Custom color palette (cyber-dark, cyber-cyan, neon-green)
- Severity-coded vulnerability badges (critical, high, medium, low)
- Responsive layout with sidebar navigation
- Custom scrollbar styling
- Smooth transitions and hover effects

## API Endpoints Used

The frontend communicates with these backend endpoints:

- `POST /start-scan` - Start a new scan
- `GET /jobs` - Get all jobs
- `GET /job/{job_id}` - Get job details
- `GET /wordlists` - Get all wordlists
- `POST /upload-wordlist` - Upload custom wordlist
- `GET /report/{report_path}` - Download report
- `GET /` - Health check

## Environment Variables

- `VITE_API_BASE_URL` - Backend API base URL (default: `http://localhost:8000`)

## Browser Support

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)

## Development Tips

1. **Hot Module Replacement**: Vite provides instant HMR for fast development
2. **Vue DevTools**: Install Vue DevTools browser extension for debugging
3. **API Proxy**: Vite's proxy configuration handles CORS in development
4. **Component Composition**: Components use Vue 3 Composition API with `<script setup>`

## Common Issues

### Backend Connection Failed

- Ensure backend is running on the configured URL
- Check CORS settings in backend
- Verify `VITE_API_BASE_URL` in `.env`

### Polling Not Working

- Check browser console for errors
- Ensure job ID is valid
- Backend must be running and accessible

### Styling Issues

- Run `npm install` to ensure TailwindCSS is installed
- Clear browser cache and rebuild
- Check `tailwind.config.js` content paths

## Contributing

1. Create a feature branch
2. Make your changes
3. Test thoroughly
4. Submit a pull request

## License

This project is part of the Autosentou automated penetration testing platform.
