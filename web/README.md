# DNS Admin Web UI

Angular 21 web administration interface for the DNS server.

## Development

```bash
# Install dependencies
npm install

# Start development server (with API proxy)
npm start
# Access at http://localhost:4200

# Build for production
npm run build
```

## Testing

```bash
# Run unit tests
npm run test:run

# Run tests in watch mode
npm test

# Run with coverage
npm run test:coverage

# Run E2E tests (headless)
npm run e2e

# Run E2E tests with browser UI
npm run e2e:headed

# Run E2E tests with Playwright UI
npm run e2e:ui
```

## Project Structure

```
src/
├── app/
│   ├── dashboard/         # Server status and statistics
│   ├── zones/             # Zone management (forward/reverse)
│   ├── records/           # DNS record CRUD
│   ├── secondary-zones/   # Secondary zone configuration
│   ├── transfer/          # Zone transfer settings
│   ├── recursion/         # Recursion settings
│   ├── dnssec/            # DNSSEC management
│   ├── network/           # Network/port settings
│   ├── settings/          # General settings
│   ├── profile/           # User profile
│   ├── login/             # Authentication
│   ├── guards/            # Route guards
│   └── services/          # API and auth services
├── e2e/                   # End-to-end tests
└── test-setup.js          # Vitest test configuration
```

## API Proxy

During development, API requests are proxied to the Go backend. Configure the proxy in `proxy.conf.json`:

```json
{
  "/api": {
    "target": "http://localhost:8080",
    "secure": false
  }
}
```

## Tech Stack

- Angular 21 (zoneless mode)
- Angular Material
- Vitest for unit testing
- Playwright for E2E testing
- RxJS
