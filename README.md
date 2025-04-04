# GHOSTED! Jobs

GHOSTED! is an application that allows users to anonymously report bad hiring practices from recruiters and hiring managers.

Similar to Glassdoor, this platform allows users to view reviews on companies. However, GHOSTED! is different because we specifically focus on negative experiences in the hiring process.

Reviews are rated from 1 Spooked (bad) to 5 Nightmare (worst).

## Key Features

### User Authentication
- Create an account anonymously using a unique username, email, and password
- Secure login system to access and create reviews
- Session management with secure session and CSRF tokens

### Data Security
- Encrypted data storage in PostgreSQL database
- Password and username hashing for enhanced security
- Protection against common web vulnerabilities

### Review System
- Submit detailed anonymous reviews about hiring experiences
- Rate companies on a scale from 1 Spooked to 5 Nightmare
- Search and filter reviews by company, industry, or rating

### Testing
- Comprehensive test suite with mock database calls
- HTML handler testing for frontend components
- Integration tests for authentication flows

## Getting Started

### Prerequisites
- Go (version X.X or higher)
- PostgreSQL database
- [Any other dependencies]

### Installation
1. Clone the repository
   ```
   git clone https://github.com/yourusername/ghostedjobs.git
   cd ghostedjobs
   ```

2. Install dependencies
   ```
   go mod download
   ```

3. Set up the database
   [Instructions for database setup]

4. Run the application
   ```
   go run main.go
   ```

## Contributing
[Instructions for contributing to the project]

## License
[License information]
