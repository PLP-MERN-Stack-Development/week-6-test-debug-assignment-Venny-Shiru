# 🧪 MERN Stack Testing & Debugging Guide

## Table of Contents
1. [Testing Environment Setup](#testing-environment-setup)
2. [Unit Testing](#unit-testing)
3. [Integration Testing](#integration-testing)
4. [End-to-End Testing](#end-to-end-testing)
5. [Debugging Techniques](#debugging-techniques)
6. [Best Practices](#best-practices)

## Testing Environment Setup

### 1. Install Testing Dependencies

```bash
# Server-side testing dependencies
npm install --save-dev jest supertest @types/jest @types/supertest

# Client-side testing dependencies
npm install --save-dev @testing-library/react @testing-library/jest-dom @testing-library/user-event jest-environment-jsdom

# End-to-end testing
npm install --save-dev cypress @cypress/react @cypress/webpack-preprocessor
# OR
npm install --save-dev @playwright/test
```

### 2. Jest Configuration

Create `jest.config.js` in your project root:

```javascript
module.exports = {
  projects: [
    {
      displayName: 'client',
      testEnvironment: 'jsdom',
      testMatch: ['<rootDir>/client/src/**/*.test.{js,jsx}'],
      setupFilesAfterEnv: ['<rootDir>/client/src/setupTests.js'],
      moduleNameMapping: {
        '^@/(.*)$': '<rootDir>/client/src/$1',
        '\\.(css|less|scss|sass)$': 'identity-obj-proxy'
      },
      transform: {
        '^.+\\.(js|jsx)$': 'babel-jest'
      }
    },
    {
      displayName: 'server',
      testEnvironment: 'node',
      testMatch: ['<rootDir>/server/**/*.test.js'],
      setupFilesAfterEnv: ['<rootDir>/server/tests/setup.js']
    }
  ],
  collectCoverageFrom: [
    'client/src/**/*.{js,jsx}',
    'server/**/*.js',
    '!**/node_modules/**',
    '!**/coverage/**',
    '!**/dist/**'
  ],
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 70,
      lines: 70,
      statements: 70
    }
  }
};
```

### 3. Package.json Scripts

```json
{
  "scripts": {
    "test": "jest",
    "test:unit": "jest --testNamePattern='Unit'",
    "test:integration": "jest --testNamePattern='Integration'",
    "test:e2e": "cypress run",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "setup-test-db": "node server/scripts/setupTestDb.js"
  }
}
```

### 4. Test Database Setup

Create `server/scripts/setupTestDb.js`:

```javascript
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

let mongoServer;

const setupTestDb = async () => {
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  
  await mongoose.connect(mongoUri);
  console.log('Test database connected');
};

const teardownTestDb = async () => {
  if (mongoServer) {
    await mongoose.connection.close();
    await mongoServer.stop();
  }
};

module.exports = { setupTestDb, teardownTestDb };
```

## Unit Testing

### 1. Server-Side Unit Tests

#### Testing Utility Functions

```javascript
// server/utils/validation.js
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const sanitizeInput = (input) => {
  return input.trim().replace(/[<>]/g, '');
};

module.exports = { validateEmail, sanitizeInput };
```

```javascript
// server/utils/__tests__/validation.test.js
const { validateEmail, sanitizeInput } = require('../validation');

describe('Unit - Validation Utils', () => {
  describe('validateEmail', () => {
    test('should return true for valid email', () => {
      expect(validateEmail('test@example.com')).toBe(true);
      expect(validateEmail('user.name@domain.co.uk')).toBe(true);
    });

    test('should return false for invalid email', () => {
      expect(validateEmail('invalid-email')).toBe(false);
      expect(validateEmail('test@')).toBe(false);
      expect(validateEmail('')).toBe(false);
    });
  });

  describe('sanitizeInput', () => {
    test('should remove HTML tags and trim whitespace', () => {
      expect(sanitizeInput('  <script>alert()</script>  ')).toBe('alert()');
      expect(sanitizeInput('Normal text')).toBe('Normal text');
    });
  });
});
```

#### Testing Express Middleware

```javascript
// server/middleware/auth.js
const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

module.exports = authMiddleware;
```

```javascript
// server/middleware/__tests__/auth.test.js
const jwt = require('jsonwebtoken');
const authMiddleware = require('../auth');

jest.mock('jsonwebtoken');

describe('Unit - Auth Middleware', () => {
  let req, res, next;

  beforeEach(() => {
    req = { header: jest.fn() };
    res = { 
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    next = jest.fn();
  });

  test('should call next() with valid token', () => {
    const mockUser = { id: 1, email: 'test@example.com' };
    req.header.mockReturnValue('Bearer validtoken');
    jwt.verify.mockReturnValue(mockUser);

    authMiddleware(req, res, next);

    expect(req.user).toEqual(mockUser);
    expect(next).toHaveBeenCalled();
  });

  test('should return 401 when no token provided', () => {
    req.header.mockReturnValue(undefined);

    authMiddleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ message: 'No token provided' });
  });
});
```

### 2. Client-Side Unit Tests

#### Testing React Components

```javascript
// client/src/components/UserCard.jsx
import React from 'react';

const UserCard = ({ user, onEdit, onDelete }) => {
  if (!user) return <div>No user data</div>;

  return (
    <div className="user-card" data-testid="user-card">
      <h3>{user.name}</h3>
      <p>{user.email}</p>
      <button onClick={() => onEdit(user.id)} data-testid="edit-btn">
        Edit
      </button>
      <button onClick={() => onDelete(user.id)} data-testid="delete-btn">
        Delete
      </button>
    </div>
  );
};

export default UserCard;
```

```javascript
// client/src/components/__tests__/UserCard.test.jsx
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import UserCard from '../UserCard';

describe('Unit - UserCard Component', () => {
  const mockUser = {
    id: 1,
    name: 'John Doe',
    email: 'john@example.com'
  };

  test('should render user information', () => {
    render(<UserCard user={mockUser} />);
    
    expect(screen.getByText('John Doe')).toBeInTheDocument();
    expect(screen.getByText('john@example.com')).toBeInTheDocument();
  });

  test('should call onEdit when edit button is clicked', () => {
    const mockOnEdit = jest.fn();
    render(<UserCard user={mockUser} onEdit={mockOnEdit} />);
    
    fireEvent.click(screen.getByTestId('edit-btn'));
    expect(mockOnEdit).toHaveBeenCalledWith(1);
  });

  test('should render "No user data" when user is null', () => {
    render(<UserCard user={null} />);
    expect(screen.getByText('No user data')).toBeInTheDocument();
  });
});
```

#### Testing Custom Hooks

```javascript
// client/src/hooks/useApi.js
import { useState, useEffect } from 'react';

const useApi = (url) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch(url);
        if (!response.ok) throw new Error('Failed to fetch');
        const result = await response.json();
        setData(result);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [url]);

  return { data, loading, error };
};

export default useApi;
```

```javascript
// client/src/hooks/__tests__/useApi.test.js
import { renderHook, waitFor } from '@testing-library/react';
import useApi from '../useApi';

// Mock fetch
global.fetch = jest.fn();

describe('Unit - useApi Hook', () => {
  beforeEach(() => {
    fetch.mockClear();
  });

  test('should return data on successful fetch', async () => {
    const mockData = { id: 1, name: 'Test' };
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockData
    });

    const { result } = renderHook(() => useApi('/api/test'));

    expect(result.current.loading).toBe(true);

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.data).toEqual(mockData);
    expect(result.current.error).toBeNull();
  });

  test('should handle fetch errors', async () => {
    fetch.mockRejectedValueOnce(new Error('Network error'));

    const { result } = renderHook(() => useApi('/api/test'));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.error).toBe('Network error');
    expect(result.current.data).toBeNull();
  });
});
```

## Integration Testing

### 1. API Integration Tests

```javascript
// server/tests/integration/users.test.js
const request = require('supertest');
const app = require('../../app');
const { setupTestDb, teardownTestDb } = require('../setup');
const User = require('../../models/User');

describe('Integration - Users API', () => {
  beforeAll(async () => {
    await setupTestDb();
  });

  afterAll(async () => {
    await teardownTestDb();
  });

  beforeEach(async () => {
    await User.deleteMany({});
  });

  describe('POST /api/users', () => {
    test('should create a new user', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/users')
        .send(userData)
        .expect(201);

      expect(response.body.user.name).toBe(userData.name);
      expect(response.body.user.email).toBe(userData.email);
      expect(response.body.user.password).toBeUndefined();
    });

    test('should return 400 for invalid email', async () => {
      const userData = {
        name: 'John Doe',
        email: 'invalid-email',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/users')
        .send(userData)
        .expect(400);

      expect(response.body.message).toContain('Invalid email');
    });
  });

  describe('GET /api/users', () => {
    test('should return all users', async () => {
      await User.create([
        { name: 'User 1', email: 'user1@example.com', password: 'pass1' },
        { name: 'User 2', email: 'user2@example.com', password: 'pass2' }
      ]);

      const response = await request(app)
        .get('/api/users')
        .expect(200);

      expect(response.body.users).toHaveLength(2);
    });
  });
});
```

### 2. Authentication Flow Tests

```javascript
// server/tests/integration/auth.test.js
const request = require('supertest');
const app = require('../../app');
const { setupTestDb, teardownTestDb } = require('../setup');
const User = require('../../models/User');

describe('Integration - Authentication Flow', () => {
  beforeAll(async () => {
    await setupTestDb();
  });

  afterAll(async () => {
    await teardownTestDb();
  });

  beforeEach(async () => {
    await User.deleteMany({});
  });

  test('should register, login, and access protected route', async () => {
    const userData = {
      name: 'Test User',
      email: 'test@example.com',
      password: 'password123'
    };

    // Register
    await request(app)
      .post('/api/auth/register')
      .send(userData)
      .expect(201);

    // Login
    const loginResponse = await request(app)
      .post('/api/auth/login')
      .send({
        email: userData.email,
        password: userData.password
      })
      .expect(200);

    const { token } = loginResponse.body;

    // Access protected route
    const profileResponse = await request(app)
      .get('/api/auth/profile')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(profileResponse.body.user.email).toBe(userData.email);
  });
});
```

### 3. React Component Integration Tests

```javascript
// client/src/components/__tests__/UserList.integration.test.jsx
import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { rest } from 'msw';
import { setupServer } from 'msw/node';
import UserList from '../UserList';

const server = setupServer(
  rest.get('/api/users', (req, res, ctx) => {
    return res(ctx.json({
      users: [
        { id: 1, name: 'John Doe', email: 'john@example.com' },
        { id: 2, name: 'Jane Smith', email: 'jane@example.com' }
      ]
    }));
  })
);

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe('Integration - UserList Component', () => {
  test('should fetch and display users', async () => {
    render(<UserList />);

    expect(screen.getByText('Loading...')).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('John Doe')).toBeInTheDocument();
      expect(screen.getByText('Jane Smith')).toBeInTheDocument();
    });
  });

  test('should handle API errors', async () => {
    server.use(
      rest.get('/api/users', (req, res, ctx) => {
        return res(ctx.status(500));
      })
    );

    render(<UserList />);

    await waitFor(() => {
      expect(screen.getByText('Error loading users')).toBeInTheDocument();
    });
  });
});
```

## End-to-End Testing

### 1. Cypress Setup

Create `cypress.config.js`:

```javascript
const { defineConfig } = require('cypress');

module.exports = defineConfig({
  e2e: {
    baseUrl: 'http://localhost:3000',
    supportFile: 'cypress/support/e2e.js',
    specPattern: 'cypress/e2e/**/*.cy.js',
    video: false,
    screenshotOnRunFailure: true,
  },
  component: {
    devServer: {
      framework: 'react',
      bundler: 'webpack',
    },
  },
});
```

### 2. User Registration and Login Flow

```javascript
// cypress/e2e/auth.cy.js
describe('E2E - Authentication Flow', () => {
  beforeEach(() => {
    cy.visit('/');
  });

  it('should register a new user', () => {
    cy.get('[data-testid="register-link"]').click();
    cy.url().should('include', '/register');

    cy.get('[data-testid="name-input"]').type('John Doe');
    cy.get('[data-testid="email-input"]').type('john@example.com');
    cy.get('[data-testid="password-input"]').type('password123');
    cy.get('[data-testid="register-button"]').click();

    cy.url().should('include', '/dashboard');
    cy.get('[data-testid="welcome-message"]').should('contain', 'Welcome, John Doe');
  });

  it('should login existing user', () => {
    cy.get('[data-testid="login-link"]').click();
    cy.url().should('include', '/login');

    cy.get('[data-testid="email-input"]').type('john@example.com');
    cy.get('[data-testid="password-input"]').type('password123');
    cy.get('[data-testid="login-button"]').click();

    cy.url().should('include', '/dashboard');
  });

  it('should handle invalid credentials', () => {
    cy.get('[data-testid="login-link"]').click();
    
    cy.get('[data-testid="email-input"]').type('invalid@example.com');
    cy.get('[data-testid="password-input"]').type('wrongpassword');
    cy.get('[data-testid="login-button"]').click();

    cy.get('[data-testid="error-message"]').should('contain', 'Invalid credentials');
  });
});
```

### 3. CRUD Operations Test

```javascript
// cypress/e2e/crud.cy.js
describe('E2E - CRUD Operations', () => {
  beforeEach(() => {
    cy.login('john@example.com', 'password123');
    cy.visit('/dashboard');
  });

  it('should create, read, update, and delete a post', () => {
    // Create
    cy.get('[data-testid="create-post-btn"]').click();
    cy.get('[data-testid="post-title"]').type('Test Post');
    cy.get('[data-testid="post-content"]').type('This is a test post content');
    cy.get('[data-testid="submit-post"]').click();

    // Read
    cy.get('[data-testid="posts-list"]').should('contain', 'Test Post');

    // Update
    cy.get('[data-testid="edit-post-btn"]').first().click();
    cy.get('[data-testid="post-title"]').clear().type('Updated Test Post');
    cy.get('[data-testid="submit-post"]').click();
    cy.get('[data-testid="posts-list"]').should('contain', 'Updated Test Post');

    // Delete
    cy.get('[data-testid="delete-post-btn"]').first().click();
    cy.get('[data-testid="confirm-delete"]').click();
    cy.get('[data-testid="posts-list"]').should('not.contain', 'Updated Test Post');
  });
});
```

### 4. Custom Cypress Commands

```javascript
// cypress/support/commands.js
Cypress.Commands.add('login', (email, password) => {
  cy.request({
    method: 'POST',
    url: '/api/auth/login',
    body: { email, password }
  }).then((response) => {
    window.localStorage.setItem('authToken', response.body.token);
  });
});

Cypress.Commands.add('seedDatabase', () => {
  cy.request('POST', '/api/test/seed-data');
});
```

## Debugging Techniques

### 1. Server-Side Debugging

#### Logging Strategy

```javascript
// server/utils/logger.js
const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'error' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

module.exports = logger;
```

#### Global Error Handler

```javascript
// server/middleware/errorHandler.js
const logger = require('../utils/logger');

const errorHandler = (err, req, res, next) => {
  logger.error(err.stack);

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(val => val.message);
    return res.status(400).json({
      message: 'Validation Error',
      errors
    });
  }

  // MongoDB duplicate key error
  if (err.code === 11000) {
    return res.status(400).json({
      message: 'Duplicate field value entered'
    });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      message: 'Invalid token'
    });
  }

  // Default error
  res.status(err.statusCode || 500).json({
    message: err.message || 'Server Error'
  });
};

module.exports = errorHandler;
```

### 2. Client-Side Debugging

#### Error Boundary Component

```javascript
// client/src/components/ErrorBoundary.jsx
import React from 'react';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Error caught by boundary:', error, errorInfo);
    
    // Log to error reporting service
    if (process.env.NODE_ENV === 'production') {
      // Send to error reporting service
      this.logErrorToService(error, errorInfo);
    }
  }

  logErrorToService = (error, errorInfo) => {
    // Implementation for error reporting service
    console.log('Logging error to service:', error, errorInfo);
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary">
          <h2>Something went wrong</h2>
          <p>We're sorry for the inconvenience. Please try refreshing the page.</p>
          {process.env.NODE_ENV === 'development' && (
            <details>
              <summary>Error details</summary>
              <pre>{this.state.error?.toString()}</pre>
            </details>
          )}
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
```

#### Custom Debug Hook

```javascript
// client/src/hooks/useDebug.js
import { useEffect } from 'react';

const useDebug = (componentName, props = {}) => {
  useEffect(() => {
    if (process.env.NODE_ENV === 'development') {
      console.group(`🔍 Debug: ${componentName}`);
      console.log('Props:', props);
      console.log('Timestamp:', new Date().toISOString());
      console.groupEnd();
    }
  }, [componentName, props]);
};

export default useDebug;
```

### 3. Performance Monitoring

```javascript
// client/src/utils/performance.js
export const measurePerformance = (name, fn) => {
  return async (...args) => {
    const start = performance.now();
    const result = await fn(...args);
    const end = performance.now();
    
    console.log(`⏱️ ${name} took ${end - start} milliseconds`);
    return result;
  };
};

// Usage
const fetchUsers = measurePerformance('fetchUsers', async () => {
  const response = await fetch('/api/users');
  return response.json();
});
```

## Best Practices

### 1. Test Organization

```
tests/
├── unit/
│   ├── client/
│   │   ├── components/
│   │   ├── hooks/
│   │   └── utils/
│   └── server/
│       ├── controllers/
│       ├── middleware/
│       └── utils/
├── integration/
│   ├── api/
│   └── components/
└── e2e/
    ├── auth/
    ├── crud/
    └── navigation/
```

### 2. Test Data Management

```javascript
// tests/fixtures/users.js
const userFixtures = {
  validUser: {
    name: 'John Doe',
    email: 'john@example.com',
    password: 'password123'
  },
  invalidUser: {
    name: '',
    email: 'invalid-email',
    password: '123'
  }
};

module.exports = userFixtures;
```

### 3. Continuous Integration

```yaml
# .github/workflows/test.yml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      mongodb:
        image: mongo:5.0
        ports:
          - 27017:27017
    
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Node.js
        uses: actions/setup-node@v2
        with:
          node-version: '16'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run unit tests
        run: npm run test:unit
      
      - name: Run integration tests
        run: npm run test:integration
      
      - name: Run E2E tests
        run: npm run test:e2e
        
      - name: Upload coverage reports
        uses: codecov/codecov-action@v1
```

### 4. Test Coverage Goals

- **Unit Tests**: 80%+ coverage for business logic
- **Integration Tests**: Cover all API endpoints
- **E2E Tests**: Cover critical user paths
- **Error Handling**: Test all error scenarios

### 5. Debugging Checklist

1. **Server Issues**:
   - Check logs for errors
   - Verify database connections
   - Test API endpoints individually
   - Check middleware execution order

2. **Client Issues**:
   - Use React DevTools
   - Check network requests
   - Verify state management
   - Check for JavaScript errors

3. **Performance Issues**:
   - Profile component renders
   - Check bundle size
   - Monitor API response times
   - Optimize database queries

This comprehensive testing and debugging guide provides a solid foundation for ensuring your MERN stack application is reliable, maintainable, and performant.