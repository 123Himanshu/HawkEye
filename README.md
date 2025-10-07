# HawkEye - Centralized Vulnerability Detection

Advanced cybersecurity dashboard for centralized vulnerability detection and intelligent security analysis.

## Features

- 🔍 **Multi-Tool Scanning** - Integrate with Nmap, Nessus, OpenVAS, Nikto, Nuclei, and OWASP ZAP
- 🤖 **AI-Powered Analysis** - Get intelligent security insights and remediation recommendations
- 📊 **Real-Time Dashboard** - Monitor security metrics and vulnerability trends
- 🎯 **Smart Targeting** - Flexible target configuration with auto-detection
- 📈 **Compliance Tracking** - Track PCI DSS, GDPR, SOC 2, and ISO 27001 compliance
- 🚨 **Priority Management** - Automatic vulnerability prioritization by severity

## Technologies

This project is built with:

- **Vite** - Fast build tool and dev server
- **TypeScript** - Type-safe JavaScript
- **React** - UI framework
- **shadcn/ui** - Beautiful component library
- **Tailwind CSS** - Utility-first CSS framework
- **Recharts** - Data visualization
- **Lucide Icons** - Modern icon library

## Getting Started

### Prerequisites

- Node.js (v18 or higher)
- npm or yarn

### Installation

```sh
# Clone the repository
git clone <YOUR_GIT_URL>

# Navigate to the project directory
cd hawkeye

# Install dependencies
npm install

# Start the development server
npm run dev
```

The application will be available at `http://localhost:8080`

### Build for Production

```sh
# Create production build
npm run build

# Preview production build
npm run preview
```

## Project Structure

```
src/
├── components/       # Reusable UI components
│   ├── ui/          # shadcn/ui components
│   └── layout/      # Layout components
├── pages/           # Page components
│   ├── Dashboard.tsx
│   ├── ScanConfig.tsx
│   └── Auth.tsx
├── hooks/           # Custom React hooks
├── data/            # Mock data and constants
└── lib/             # Utility functions
```

## Usage

1. **Login** - Use the authentication page to access the dashboard
2. **Configure Scan** - Set up your target and select scanning tools
3. **Run Scan** - Execute the security scan
4. **View Results** - Analyze vulnerabilities and security metrics
5. **AI Analysis** - Get AI-powered insights and remediation steps

## Security Features

- **Vulnerability Detection** - Identify security weaknesses across your infrastructure
- **Risk Assessment** - Evaluate and prioritize security risks
- **Compliance Monitoring** - Track compliance with security frameworks
- **Automated Scanning** - Schedule and automate security scans
- **Detailed Reporting** - Generate comprehensive security reports

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.

## Support

For support and questions, please open an issue in the repository.
