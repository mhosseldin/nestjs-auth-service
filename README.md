# AuthService (Work-in-Progress)

This project is a **modular authentication and authorization service** built with [NestJS](https://nestjs.com/), [Prisma](https://www.prisma.io/), and JWT-based access/refresh token flows.

⚠️ **Status**: Under Development.  
The service is functional for basic flows (registration, login, email verification, logout, etc.) but is not yet feature-complete.

---

## ✅ Current Features

### 1. **User Registration**

- Register with email & password.
- Email verification flow (with resend & throttling).
- Audit logging of all registration-related events.

### 2. **Login**

- Secure login with email & password.
- Issues **JWT access & refresh tokens**.
- Refresh token rotation implemented.
- Logout with refresh token revocation.
- `/me` endpoint for authenticated profile lookup.
- Throttling & audit logging in place.

### 3. **Authorization**

- Role-based access control (RBAC) using decorators & `RolesGuard`.
- Verified email guard for restricting unverified accounts.
- Ownership helper for resource-level checks.
- Audit logging for failed access attempts (invalid token, expired, insufficient role).
- Audit logging for sensitive actions (e.g., admin operations).

---

## 🛠️ Tech Stack

- **Backend**: [NestJS](https://nestjs.com/)
- **Database**: [PostgreSQL](https://www.postgresql.org/) with [Prisma ORM](https://www.prisma.io/)
- **Auth**: JWT (Access + Refresh, rotation, hashing)
- **Guards/Decorators**: RolesGuard, VerifiedEmailGuard, Ownership checks
- **Audit Logging**: Prisma-powered audit log table

---

## 🚀 Running Locally

### Prerequisites

Before running the service, ensure you have:

- **Node.js** (LTS version recommended)
- **npm** (Node Package Manager)
- **PostgreSQL** server running and accessible. Create a database named `authdb` (or as configured in `DATABASE_URL`).

### 1. Clone the repository

```bash
git clone https://github.com/mhosseldin/nestjs-auth-service
```

### 2. Install dependencies

```bash
npm install
```

### 3. Setup environment variables

Create a `.env` file in the project root with the following variables:

```ini
DATABASE_URL="postgresql://user:password@localhost:5432/authdb?schema=public"
ACCESS_TOKEN_SECRET=your_access_secret
REFRESH_TOKEN_SECRET=your_refresh_secret
ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL=14d
JWT_ISSUER=auth-service
JWT_AUDIENCE=your-app
```

**Note**: Replace `user`, `password`, and `authdb` with your PostgreSQL credentials and database name. Ensure `ACCESS_TOKEN_SECRET` and `REFRESH_TOKEN_SECRET` are strong, randomly generated strings.

### 4. Run Prisma migrations

```bash
npx prisma migrate dev
```

### 5. Start the service

```bash
npm run start:dev
```

The service will be running at `http://localhost:3000` (or your configured port).
